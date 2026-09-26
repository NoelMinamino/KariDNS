#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_query_engine.h"
#include "dns_server_internal.h"
#include "dns_dynamic_update.h"
#include "dns_catalog_zone.h"
#include "dns_axfr_ixfr.h"
#include "dns_rrl.h"
#include "dns_edns_ecs.h"
#include "dns_dnstap.h"
#include "dns_utils.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include "sweep_watchdog.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>

// Mock globals
int g_control_kq = -1;
int g_notify_ipc[2] = {-1, -1};
int g_broker_sock = -1;
config_rcu_t g_config_db;
_Atomic int g_xfers_running = 0;
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
int g_cwd_fd = -1;
char g_startup_cwd[PATH_MAX] = "";

void syslog(int priority, const char *format, ...) {
    (void)priority;
    if (getenv("SW_SYSLOG")) {           /* debugging aid: SW_SYSLOG=1 ./test_coverage_sweep */
        va_list ap; va_start(ap, format); vfprintf(stderr, format, ap); va_end(ap); fputc('\n', stderr);
    }
}

server_config_t *acquire_config_snapshot(void) {
    return atomic_load_explicit(&g_config_db.active, memory_order_acquire);
}
void release_config_snapshot(server_config_t *snap) { (void)snap; }

/* Real (non-privileged) implementations so the forward-zone code can talk to
 * the in-process fake forwarder below. g_broker_fail forces the error path. */
static int g_broker_fail;
int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len) {
    if (g_broker_fail) return -1;
    int fd = socket(family, type, 0);
    if (fd < 0) return -1;
    if (connect(fd, addr, (socklen_t)addr_len) != 0) { close(fd); return -1; }
    return fd;
}

/* send_tcp_robust() captures the AXFR server's output so it can be replayed to
 * the secondary-side parser; fd == -2 simulates a broken connection. */
static uint8_t *g_cap; static size_t g_cap_len, g_cap_cap; static bool g_cap_on;
ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len) {
    if (fd == -2) return -1;
    if (g_cap_on) {
        if (g_cap_len + len > g_cap_cap) { g_cap_cap = (g_cap_len + len) * 2 + 65536; g_cap = realloc(g_cap, g_cap_cap); }
        memcpy(g_cap + g_cap_len, buf, len); g_cap_len += len;
    }
    return (ssize_t)len;
}

/* Minimal blocking reader: 2-byte length prefix + message. 1 = ok, 0 = EOF, -1 = error. */
int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out) {
    (void)ctx;
    static uint8_t mbuf[65536];
    uint8_t lp[2];
    ssize_t n = recv(fd, lp, 2, MSG_WAITALL);
    if (n == 0) return 0;
    if (n != 2) return -1;
    uint16_t l = (uint16_t)((lp[0] << 8) | lp[1]);
    if (l && recv(fd, mbuf, l, MSG_WAITALL) != l) return -1;
    *msg_out = mbuf; *msg_len_out = l;
    return 1;
}

void submit_response_log(log_action_t action, const char *client_ip, int client_port,
                        const char *qname, uint16_t qclass, uint16_t qtype,
                        uint8_t rcode, bool has_edns, bool dnssec_ok) {
    (void)action; (void)client_ip; (void)client_port; (void)qname;
    (void)qclass; (void)qtype; (void)rcode; (void)has_edns; (void)dnssec_ok;
}

void dec_tcp_clients(void) {}
void inc_tcp_clients(void) {}

size_t resolve_ip_port_to_sockaddr(const char *ip, int port, struct sockaddr_storage *out) {
    memset(out, 0, sizeof(*out));
    struct sockaddr_in *s4 = (struct sockaddr_in *)out;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out;
    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET; s4->sin_port = htons((uint16_t)port);
        return sizeof(*s4);
    }
    if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6; s6->sin6_port = htons((uint16_t)port);
        return sizeof(*s6);
    }
    return 0;
}

/* ===========================================================================
 * test_coverage_sweep.c
 *
 * Systematic "sweep" tests aimed at branch coverage of the query engine:
 *   - a feature-rich zone (DNSSEC NSEC + NSEC3, delegations, glue, CNAME/DNAME
 *     chains, wildcards, ENTs, large RRsets) is queried for every
 *     (name, type, EDNS mode) combination under several server configs;
 *   - selected queries are replayed with every response-buffer limit from the
 *     header size up to a full UDP payload, so every "buffer exhausted -> TC"
 *     error branch in resolve_name()/find_delegation()/glue/NSEC attachment
 *     is executed;
 *   - every valid query is truncated byte-by-byte and bit-mutated to drive the
 *     request parsing / FORMERR paths.
 * The invariants checked are the ones that must hold for *any* input:
 * no crash, the response fits the limit, ID is echoed, QR is set.
 * ======================================================================== */

#define SW_RES_CAP 70000

typedef struct {
    zone_arena_t arena[8];
    zone_db_entry_t entry[8];
    zone_db_entry_t *entries[8];
    char *acl[1];
    view_snapshot_t view;
    zone_db_snapshot_t snap;
    server_config_t *cfg;
    int zone_count;
} sw_env_t;

static sw_env_t g_sw;
static uint8_t g_res[SW_RES_CAP];
static unsigned long g_calls;

static server_config_t *sw_conf(const char *text) {
    server_config_t *cfg = calloc(1, sizeof(*cfg));
    assert(cfg);
    int rc = parse_named_conf(text, cfg);
    if (rc != 0) { fprintf(stderr, "config failed:\n%s\n", text); assert(0); }
    return cfg;
}

static void sw_add_zone(const char *origin, const char *text) {
    int i = g_sw.zone_count++;
    assert(i < 8);
    zone_arena_t *a = &g_sw.arena[i];
    zone_arena_init(a);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = origin,
                            .is_standalone_mode = true, .err_out = &err };
    char *buf = arena_strdup(a, text);
    assert(buf);
    int prc = parse_zone_fast(buf, strlen(buf), a, &ctx);
    if (prc < 0) { fprintf(stderr, "zone %s parse failed at %zu: %s\n", origin, err.error_offset, err.error_message ? err.error_message : "?"); assert(0); }
    assert(build_zone_index(a, true) == 0);
    zone_db_entry_t *e = &g_sw.entry[i];
    strncpy(e->domain, origin, sizeof(e->domain) - 1);
    strncpy(e->view_name, "default", sizeof(e->view_name) - 1);
    pthread_mutex_init(&e->writer_lock, NULL);
    atomic_store_explicit(&e->rcu.active, a, memory_order_release);
    g_sw.entries[i] = e;
}

static void sw_finish_view(void) {
    g_sw.acl[0] = (char *)"any";
    g_sw.view.name = "default";
    g_sw.view.entries = g_sw.entries;
    g_sw.view.zone_count = (size_t)g_sw.zone_count;
    g_sw.view.match_clients = g_sw.acl;
    g_sw.view.match_clients_count = 1;
    g_sw.snap.views = &g_sw.view;
    g_sw.snap.view_count = 1;
}

static void sw_teardown(void) {
    for (int i = 0; i < g_sw.zone_count; i++) {
        zone_arena_destroy(&g_sw.arena[i]);
        pthread_mutex_destroy(&g_sw.entry[i].writer_lock);
    }
    if (g_sw.cfg) { free_server_config_fields(g_sw.cfg); free(g_sw.cfg); }
    memset(&g_sw, 0, sizeof(g_sw));
}

/* ---- query builder ------------------------------------------------------ */

enum {
    Q_EDNS      = 1u << 0,
    Q_DO        = 1u << 1,
    Q_COOKIE    = 1u << 2,   /* client cookie only           */
    Q_NSID      = 1u << 3,
    Q_ECS4      = 1u << 4,
    Q_ECS6      = 1u << 5,
    Q_KEEPALIVE = 1u << 6,
    Q_MQTYPE    = 1u << 7,
    Q_EDE       = 1u << 8,
    Q_PAD       = 1u << 9,   /* unknown option (padding)     */
    Q_BIGPAY    = 1u << 10,  /* UDP payload 4096 vs 1232     */
    Q_SMALLPAY  = 1u << 11,  /* UDP payload 256 (<512)       */
    Q_CO        = 1u << 12,  /* compact-answers bit          */
    Q_BADCOOKIE = 1u << 13,  /* malformed cookie length      */
    Q_SRVCOOKIE = 1u << 14,  /* client + (bogus) server cookie */
    Q_VERSION1  = 1u << 15,  /* EDNS version 1 -> BADVERS    */
};

static size_t sw_build(uint8_t *buf, uint16_t id, uint8_t flags2, uint8_t flags3,
                       const char *qname, uint16_t qtype, uint16_t qclass, unsigned q) {
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(id >> 8); buf[1] = (uint8_t)id;
    buf[2] = flags2; buf[3] = flags3;
    buf[5] = 1;
    long wlen = write_uncompressed_name(buf, 12, 300, qname);
    assert(wlen > 0);
    size_t off = 12 + (size_t)wlen;
    buf[off++] = (uint8_t)(qtype >> 8); buf[off++] = (uint8_t)qtype;
    buf[off++] = (uint8_t)(qclass >> 8); buf[off++] = (uint8_t)qclass;
    if (!(q & Q_EDNS)) return off;
    buf[11] = 1;
    buf[off++] = 0; buf[off++] = 0; buf[off++] = 41;
    uint16_t pay = (q & Q_BIGPAY) ? 4096 : (q & Q_SMALLPAY) ? 256 : 1232;
    buf[off++] = (uint8_t)(pay >> 8); buf[off++] = (uint8_t)pay;
    buf[off++] = 0;                                   /* ext rcode */
    buf[off++] = (q & Q_VERSION1) ? 1 : 0;            /* version   */
    buf[off++] = (uint8_t)(((q & Q_DO) ? 0x80 : 0) | ((q & Q_CO) ? 0x40 : 0));
    buf[off++] = 0;
    size_t rdlen_pos = off; off += 2;
    size_t rd_start = off;
    if (q & Q_COOKIE) {
        buf[off++] = 0; buf[off++] = 10; buf[off++] = 0; buf[off++] = 8;
        for (int i = 0; i < 8; i++) buf[off++] = (uint8_t)(0xA0 + i);
    }
    if (q & Q_SRVCOOKIE) {
        buf[off++] = 0; buf[off++] = 10; buf[off++] = 0; buf[off++] = 24;
        for (int i = 0; i < 24; i++) buf[off++] = (uint8_t)(0x11 * (i + 1));
    }
    if (q & Q_BADCOOKIE) {
        buf[off++] = 0; buf[off++] = 10; buf[off++] = 0; buf[off++] = 5;
        for (int i = 0; i < 5; i++) buf[off++] = 0x55;
    }
    if (q & Q_NSID) { buf[off++] = 0; buf[off++] = 3; buf[off++] = 0; buf[off++] = 0; }
    if (q & Q_ECS4) {
        buf[off++] = 0; buf[off++] = 8; buf[off++] = 0; buf[off++] = 7;
        buf[off++] = 0; buf[off++] = 1; buf[off++] = 24; buf[off++] = 0;
        buf[off++] = 198; buf[off++] = 51; buf[off++] = 100;
    }
    if (q & Q_ECS6) {
        buf[off++] = 0; buf[off++] = 8; buf[off++] = 0; buf[off++] = 10;
        buf[off++] = 0; buf[off++] = 2; buf[off++] = 48; buf[off++] = 0;
        buf[off++] = 0x20; buf[off++] = 0x01; buf[off++] = 0x0d; buf[off++] = 0xb8;
        buf[off++] = 0x00; buf[off++] = 0x01;
    }
    if (q & Q_KEEPALIVE) { buf[off++] = 0; buf[off++] = 11; buf[off++] = 0; buf[off++] = 0; }
    if (q & Q_MQTYPE) {
        buf[off++] = 0; buf[off++] = 20; buf[off++] = 0; buf[off++] = 4;
        buf[off++] = 0; buf[off++] = 28; buf[off++] = 0; buf[off++] = 16;   /* AAAA, TXT */
    }
    if (q & Q_EDE) {
        buf[off++] = 0; buf[off++] = 15; buf[off++] = 0; buf[off++] = 5;
        buf[off++] = 0; buf[off++] = 3; buf[off++] = 'a'; buf[off++] = 'b'; buf[off++] = 'c';
    }
    if (q & Q_PAD) {
        buf[off++] = 0; buf[off++] = 12; buf[off++] = 0; buf[off++] = 6;
        for (int i = 0; i < 6; i++) buf[off++] = 0;
    }
    uint16_t rdlen = (uint16_t)(off - rd_start);
    buf[rdlen_pos] = (uint8_t)(rdlen >> 8); buf[rdlen_pos + 1] = (uint8_t)rdlen;
    return off;
}

/* Runs one query and checks the invariants that must hold for any input. */
static int sw_run(const uint8_t *req, size_t req_len, size_t max_res, const char *qname,
                  uint16_t qtype, const char *client_ip, bool tcp) {
    static compress_ctx_t comp;
    static bool comp_init;
    if (!comp_init) { compress_ctx_init(&comp); comp_init = true; }
    rate_limit_config_t *rrl = NULL;
    zone_db_entry_t *matched = NULL;
    g_calls++;
    int n = process_dns_query_impl(req, req_len, g_res, max_res, qname, qtype, client_ip,
                                   &comp, tcp, &rrl, &g_sw.snap, g_sw.cfg, &matched);
    assert(n >= -1);            /* -1 == drop (unparseable question) */
    if (n > 0 && (size_t)n > (max_res > 1232 ? max_res : 1232)) {
        fprintf(stderr, "OVERSIZE: %s type %u len %d limit %zu tcp %d reqlen %zu\n", qname, qtype, n, max_res, tcp, req_len);
        assert(0);
    }
    if (n >= 12 && req_len >= 2) {
        assert(g_res[0] == req[0] && g_res[1] == req[1]);
        assert(g_res[2] & 0x80);
    }
    return n;
}

/* ---- zone material ------------------------------------------------------ */

#define SIG(t) " IN RRSIG " t " 8 2 3600 20400101000000 20200101000000 4711 example. " \
    "AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=\n"

static const char *ZONE_EXAMPLE =
    "$ORIGIN example.\n$TTL 3600\n"
    "@ IN SOA ns1.example. hostmaster.example. 2026092501 7200 3600 1209600 300\n"
    "@" SIG("SOA")
    "@ IN NS ns1.example.\n@ IN NS ns2.example.\n@ IN NS ns.other.test.\n"
    "@" SIG("NS")
    "@ IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF\n"
    "@" SIG("DNSKEY")
    "@ IN MX 10 mail.example.\n@ IN MX 20 mail.other.test.\n@ IN MX 30 sub.example.\n"
    "@" SIG("MX")
    "@ IN TXT \"v=spf1 -all\"\n"
    "@ IN HINFO \"x86\" \"FreeBSD\"\n"
    "@ IN NSEC _sip._tcp.example. A NS SOA MX TXT RRSIG NSEC DNSKEY HINFO\n"
    "@" SIG("NSEC")
    "_sip._tcp IN SRV 10 60 5060 www.example.\n_sip._tcp IN SRV 20 60 5060 ns.other.test.\n"
    "_sip._tcp" SIG("SRV")
    "_sip._tcp IN NSEC a.b.ent.example. SRV RRSIG NSEC\n"
    "a.b.ent IN A 192.0.2.77\n"
    "a.b.ent IN NSEC big.example. A RRSIG NSEC\n"
    "big IN A 192.0.2.1\nbig IN A 192.0.2.2\nbig IN A 192.0.2.3\nbig IN A 192.0.2.4\n"
    "big IN A 192.0.2.5\nbig IN A 192.0.2.6\nbig IN A 192.0.2.7\nbig IN A 192.0.2.8\n"
    "big IN A 192.0.2.9\nbig IN A 192.0.2.10\nbig IN A 192.0.2.11\nbig IN A 192.0.2.12\n"
    "big IN TXT \"0123456789012345678901234567890123456789012345678901234567890123456789\"\n"
    "big IN TXT \"abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij\"\n"
    "big IN TXT \"ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ\"\n"
    "big" SIG("A")
    "big IN NSEC c1.example. A TXT RRSIG NSEC\n"
    "c1 IN CNAME c2.example.\n" "c1" SIG("CNAME")
    "c1 IN NSEC c2.example. CNAME RRSIG NSEC\n"
    "c2 IN CNAME www.example.\n" "c2" SIG("CNAME")
    "c2 IN NSEC cext.example. CNAME RRSIG NSEC\n"
    "cext IN CNAME www.other.test.\n"
    "cext IN NSEC cloop1.example. CNAME RRSIG NSEC\n"
    "cloop1 IN CNAME cloop2.example.\ncloop2 IN CNAME cloop1.example.\n"
    "cnx IN CNAME nothere.example.\n"
    "cwild IN CNAME foo.wild.example.\n"
    "cdn IN CNAME x.d.example.\n"
    "d IN DNAME target.example.\n" "d" SIG("DNAME")
    "d IN NSEC ins.example. DNAME RRSIG NSEC\n"
    "dlong IN DNAME aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.example.\n"
    "ins IN NS ns.ins.example.\nns.ins IN A 192.0.2.60\nns.ins IN AAAA 2001:db8::60\n"
    "ins IN NSEC mail.example. NS RRSIG NSEC\n"
    "mail IN A 192.0.2.25\nmail IN AAAA 2001:db8::25\n" "mail" SIG("A")
    "mail IN NSEC ns1.example. A AAAA RRSIG NSEC\n"
    "ns1 IN A 192.0.2.53\nns1 IN AAAA 2001:db8::53\n" "ns1" SIG("A")
    "ns1 IN NSEC ns2.example. A AAAA RRSIG NSEC\n"
    "ns2 IN A 192.0.2.54\n"
    "ns2 IN NSEC sub.example. A RRSIG NSEC\n"
    "sub IN NS ns.sub.example.\nsub IN NS ns.other.test.\n"
    "sub IN DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE75E67E0C3E9E8B6B1E6A63E7\n"
    "sub" SIG("DS")
    "sub IN NSEC target.example. NS DS RRSIG NSEC\n"
    "sub" SIG("NSEC")
    "ns.sub IN A 192.0.2.61\nns.sub IN AAAA 2001:db8::61\n"
    "target IN A 192.0.2.99\n"
    "x.target IN A 192.0.2.98\n"
    "target IN NSEC *.wild.example. A RRSIG NSEC\n"
    "*.wild IN A 192.0.2.200\n*.wild IN TXT \"wildcard\"\n*.wild IN MX 10 mail.example.\n"
    "*.wild" SIG("A")
    "*.wild IN NSEC www.example. A TXT MX RRSIG NSEC\n"
    "exact.wild IN A 192.0.2.201\n"
    "www IN A 192.0.2.80\nwww IN AAAA 2001:db8::80\nwww IN TXT \"hello\"\n"
    "www" SIG("A") "www" SIG("AAAA")
    "www IN NSEC example. A AAAA TXT RRSIG NSEC\n"
    "www" SIG("NSEC")
    "ptr IN PTR www.example.\n"
    "caa IN CAA 0 issue \"ca.example\"\n"
    "sshfp IN SSHFP 1 1 123456789abcdef67890123456789abcdef67890\n"
    "svc IN SVCB 1 www.example. alpn=h2 port=8443\n"
    "https IN HTTPS 1 . alpn=h3\n"
    "naptr IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example!\" .\n"
    "loc IN LOC 51 30 12.748 N 0 7 39.611 W 45.00m 1m 1m 1m\n"
    "rp IN RP hostmaster.example. www.example.\n"
    "afs IN AFSDB 1 www.example.\n"
    "kx IN KX 10 www.example.\n"
    "nullrec IN TYPE65000 \\# 4 DEADBEEF\n";

static const char *ZONE_OTHER =
    "$ORIGIN other.test.\n$TTL 300\n"
    "@ IN SOA ns.other.test. h.other.test. 1 7200 3600 1209600 60\n"
    "@ IN NS ns.other.test.\n"
    "ns IN A 203.0.113.53\nns IN AAAA 2001:db8:1::53\n"
    "www IN A 203.0.113.80\n"
    "mail IN A 203.0.113.25\n";

/* Location / ECS steered zone: every structural element also exists in a
 * tagged-only variant so that the "record not valid for this client -> skip"
 * branches are taken in glue, delegation, DS, NSEC, CNAME, DNAME and wildcard code. */
static const char *ZONE_GEO =
    "$ORIGIN geo.test.\n$TTL 300\n"
    "$LOCATION-TAG office 10.0.0.0/8\n"
    "$ECS-SUBNET-TAG eu 198.51.100.0/24 2001:db8::/32\n"
    "@ IN SOA ns.geo.test. h.geo.test. 3 7200 3600 1209600 60\n"
    "@ IN NS ns.geo.test.\n"
    "ns IN A 192.0.2.1\n"
    "www IN A 192.0.2.80\n"
    "mx IN MX 10 www.geo.test.\n"
    "mx IN MX 20 ns2.geo.test.\n"
    "del IN NS ns.del.geo.test.\n"
    "ns.del IN A 192.0.2.9\n"
    "del IN NSEC ns.geo.test. NS NSEC\n"
    "$LOCATION office\n"
    "@ IN NS ns2.geo.test.\n"
    "ns2 IN A 10.0.0.2\n"
    "ns IN A 10.0.0.1\n"
    "www IN A 10.0.0.80\n"
    "cn IN CNAME www.geo.test.\n"
    "dn IN DNAME www.geo.test.\n"
    "*.wc IN A 10.9.9.9\n"
    "*.wcc IN CNAME www.geo.test.\n"
    "del IN DS 1 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE75E67E0C3E9E8B6B1E6A63E7\n"
    "ns.del IN A 10.0.0.9\n"
    "tagged IN NSEC www.geo.test. A NSEC\n"
    "tagged IN A 10.0.0.7\n"
    "$LOCATION default\n"
    "$ECS-SUBNET eu\n"
    "www IN A 198.51.100.80\n"
    "cn2 IN CNAME www.geo.test.\n"
    "dn2 IN DNAME www.geo.test.\n"
    "*.wc IN A 198.51.100.9\n"
    "eu-only IN TXT \"eu\"\n"
    "$ECS-SUBNET default\n"
    "any IN HINFO \"a\" \"b\"\n";

/* Apex SOA visible only to the office location: negative answers for other
 * clients have to cope with "no SOA found". */
static const char *ZONE_NOSOA =
    "$ORIGIN nosoa.test.\n$TTL 300\n"
    "$LOCATION-TAG office 10.0.0.0/8\n"
    "$LOCATION office\n"
    "@ IN SOA ns.nosoa.test. h.nosoa.test. 1 7200 3600 1209600 60\n"
    "$LOCATION default\n"
    "@ IN NS ns.nosoa.test.\n"
    "ns IN A 192.0.2.44\n"
    "www IN A 192.0.2.45\n";

/* NSEC3 zone text is generated at run time so that owner hashes are real. */
static char *make_nsec3_zone(bool optout) {
    const char *names[] = { "n3.example.", "www.n3.example.", "a.n3.example.",
                            "del.n3.example.", "*.w.n3.example.", "w.n3.example." };
    const int nn = (int)(sizeof(names) / sizeof(names[0]));
    char hashes[8][64];
    const uint8_t salt[2] = { 0xAB, 0xCD };
    for (int i = 0; i < nn; i++)
        assert(compute_nsec3_hash(names[i], 1, 2, salt, sizeof(salt), hashes[i], sizeof(hashes[i])));
    /* sort hashes */
    int order[8];
    for (int i = 0; i < nn; i++) order[i] = i;
    for (int i = 0; i < nn; i++)
        for (int j = i + 1; j < nn; j++)
            if (strcasecmp(hashes[order[j]], hashes[order[i]]) < 0) { int t = order[i]; order[i] = order[j]; order[j] = t; }
    const char *types[] = { "SOA NS DNSKEY NSEC3PARAM RRSIG", "A AAAA RRSIG", "A RRSIG",
                            "NS", "A TXT RRSIG", "" };
    char *z = malloc(16384);
    assert(z);
    int o = snprintf(z, 16384,
        "$ORIGIN n3.example.\n$TTL 600\n"
        "@ IN SOA ns.n3.example. h.n3.example. 7 7200 3600 1209600 120\n"
        "@ IN NS ns.n3.example.\n"
        "@ IN NSEC3PARAM 1 0 2 ABCD\n"
        "ns IN A 192.0.2.3\n"
        "www IN A 192.0.2.4\nwww IN AAAA 2001:db8::4\n"
        "www IN RRSIG A 8 3 600 20400101000000 20200101000000 4711 n3.example. AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF\n"
        "a IN A 192.0.2.5\n"
        "del IN NS ns.del.n3.example.\nns.del IN A 192.0.2.6\n"
        "*.w IN A 192.0.2.7\n*.w IN TXT \"w\"\n");
    for (int k = 0; k < nn; k++) {
        int i = order[k], nx = order[(k + 1) % nn];
        o += snprintf(z + o, 16384 - o, "%s IN NSEC3 1 %d 2 ABCD %s %s\n",
                      hashes[i], optout ? 1 : 0, hashes[nx], types[i]);
        o += snprintf(z + o, 16384 - o,
                      "%s IN RRSIG NSEC3 8 3 600 20400101000000 20200101000000 4711 n3.example. AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29\n",
                      hashes[i]);
    }
    return z;
}

/* ---- matrix ------------------------------------------------------------- */

static const char *SW_NAMES[] = {
    "example.", "www.example.", "WWW.Example.", "mail.example.", "big.example.",
    "c1.example.", "c2.example.", "cext.example.", "cloop1.example.", "cnx.example.",
    "cwild.example.", "cdn.example.", "x.d.example.", "y.x.d.example.", "d.example.",
    "q.dlong.example.", "ins.example.", "host.ins.example.", "sub.example.",
    "deep.host.sub.example.", "ns.sub.example.", "foo.wild.example.", "a.b.wild.example.",
    "exact.wild.example.", "b.ent.example.", "ent.example.", "a.b.ent.example.",
    "nx.example.", "zzz.example.", "_sip._tcp.example.", "ptr.example.", "caa.example.",
    "svc.example.", "https.example.", "naptr.example.", "loc.example.", "rp.example.",
    "afs.example.", "kx.example.", "nullrec.example.", "sshfp.example.", "target.example.",
    "x.target.example.",
    "n3.example.", "www.n3.example.", "a.n3.example.", "nx.n3.example.", "x.y.n3.example.",
    "host.del.n3.example.", "del.n3.example.", "q.w.n3.example.", "w.n3.example.",
    "other.test.", "www.other.test.", "nx.other.test.",
    "unrelated.invalid.", ".",
    "geo.test.", "ns.geo.test.", "www.geo.test.", "mx.geo.test.", "cn.geo.test.", "cn2.geo.test.",
    "x.dn.geo.test.", "x.dn2.geo.test.", "a.wc.geo.test.", "a.wcc.geo.test.", "host.del.geo.test.",
    "del.geo.test.", "tagged.geo.test.", "eu-only.geo.test.", "any.geo.test.", "nx.geo.test.",
    "nosoa.test.", "www.nosoa.test.", "nx.nosoa.test.",
};
static const uint16_t SW_TYPES[] = { 1, 28, 2, 6, 15, 16, 5, 39, 12, 33, 43, 48, 47, 50, 46,
                                     13, 255, 99, 64, 65, 257, 35, 29, 17, 18, 36, 65000, 51, 10, 252, 251 };
static const unsigned SW_MODES[] = {
    0, Q_EDNS, Q_EDNS | Q_DO, Q_EDNS | Q_DO | Q_BIGPAY, Q_EDNS | Q_SMALLPAY | Q_DO,
    Q_EDNS | Q_COOKIE | Q_NSID, Q_EDNS | Q_ECS4, Q_EDNS | Q_ECS6 | Q_DO,
    Q_EDNS | Q_MQTYPE, Q_EDNS | Q_EDE | Q_PAD | Q_KEEPALIVE, Q_EDNS | Q_CO | Q_DO,
    Q_EDNS | Q_BADCOOKIE, Q_EDNS | Q_SRVCOOKIE | Q_DO, Q_EDNS | Q_VERSION1,
};
#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

static void sw_matrix(bool tcp_too) {
    uint8_t req[512];
    for (size_t n = 0; n < NELEM(SW_NAMES); n++) {
        for (size_t t = 0; t < NELEM(SW_TYPES); t++) {
            for (size_t m = 0; m < NELEM(SW_MODES); m++) {
                size_t len = sw_build(req, (uint16_t)(n * 97 + t * 7 + m), 0x01, 0x00,
                                      SW_NAMES[n], SW_TYPES[t], 1, SW_MODES[m]);
                static const char *ips[] = { "192.0.2.100", "10.1.2.3", "127.0.0.1", "2001:db8::1" };
                const char *ip = ips[(n + t + m) % 4];
                sw_run(req, len, 512, SW_NAMES[n], SW_TYPES[t], ip, false);
                if (tcp_too && (m % 3) == 0)
                    sw_run(req, len, 65535, SW_NAMES[n], SW_TYPES[t], ip, true);
            }
        }
    }
}

/* Every response-size limit from the header size upward. */
static void sw_truncation_sweep(void) {
    struct { const char *name; uint16_t type; unsigned mode; } cases[] = {
        { "www.example.", 1, Q_EDNS | Q_DO }, { "www.example.", 255, Q_EDNS | Q_DO },
        { "www.example.", 255, 0 },           { "example.", 15, Q_EDNS | Q_DO },
        { "example.", 2, Q_EDNS | Q_DO },     { "example.", 48, Q_EDNS | Q_DO },
        { "example.", 6, Q_EDNS | Q_DO },     { "big.example.", 1, Q_EDNS | Q_DO },
        { "big.example.", 16, 0 },            { "c1.example.", 1, Q_EDNS | Q_DO },
        { "cext.example.", 1, Q_EDNS | Q_DO },{ "x.d.example.", 1, Q_EDNS | Q_DO },
        { "cdn.example.", 1, Q_EDNS | Q_DO }, { "sub.example.", 43, Q_EDNS | Q_DO },
        { "host.sub.example.", 1, Q_EDNS | Q_DO }, { "host.sub.example.", 1, 0 },
        { "host.ins.example.", 1, Q_EDNS | Q_DO }, { "foo.wild.example.", 1, Q_EDNS | Q_DO },
        { "foo.wild.example.", 15, Q_EDNS | Q_DO }, { "foo.wild.example.", 28, Q_EDNS | Q_DO },
        { "nx.example.", 1, Q_EDNS | Q_DO },  { "b.ent.example.", 1, Q_EDNS | Q_DO },
        { "www.example.", 16, Q_EDNS | Q_DO }, { "_sip._tcp.example.", 33, Q_EDNS | Q_DO },
        { "_sip._tcp.example.", 33, 0 },      { "mail.example.", 28, Q_EDNS | Q_DO },
        { "nx.n3.example.", 1, Q_EDNS | Q_DO }, { "www.n3.example.", 16, Q_EDNS | Q_DO },
        { "x.y.n3.example.", 1, Q_EDNS | Q_DO }, { "host.del.n3.example.", 1, Q_EDNS | Q_DO },
        { "q.w.n3.example.", 28, Q_EDNS | Q_DO }, { "q.w.n3.example.", 1, Q_EDNS | Q_DO },
        { "www.example.", 1, Q_EDNS | Q_COOKIE | Q_NSID | Q_MQTYPE | Q_DO },
        { "cwild.example.", 1, Q_EDNS | Q_DO },
    };
    uint8_t req[512];
    for (size_t c = 0; c < NELEM(cases); c++) {
        size_t len = sw_build(req, (uint16_t)(0x5000 + c), 0x01, 0, cases[c].name, cases[c].type, 1, cases[c].mode);
        for (size_t lim = 12; lim <= 700; lim++)
            sw_run(req, len, lim, cases[c].name, cases[c].type, "192.0.2.100", false);
        for (size_t lim = 12; lim <= 700; lim += 7)
            sw_run(req, len, lim, cases[c].name, cases[c].type, "192.0.2.100", true);
    }
}

/* Truncated and bit-flipped variants of valid queries. */
static void sw_mutation_sweep(void) {
    const char *names[] = { "www.example.", "sub.example.", "nx.n3.example.", "foo.wild.example." };
    unsigned modes[] = { 0, Q_EDNS | Q_DO | Q_COOKIE | Q_ECS4 | Q_NSID | Q_MQTYPE, Q_EDNS | Q_ECS6 | Q_EDE };
    uint8_t req[512], mut[512];
    for (size_t n = 0; n < NELEM(names); n++) {
        for (size_t m = 0; m < NELEM(modes); m++) {
            size_t len = sw_build(req, 0x7777, 0x01, 0, names[n], 1, 1, modes[m]);
            for (size_t cut = 0; cut <= len; cut++) {
                memcpy(mut, req, cut);
                sw_run(mut, cut, 512, names[n], 1, "192.0.2.100", false);
            }
            for (size_t pos = 0; pos < len; pos++) {
                for (int bit = 0; bit < 8; bit++) {
                    memcpy(mut, req, len);
                    mut[pos] ^= (uint8_t)(1u << bit);
                    sw_run(mut, len, 512, names[n], 1, "192.0.2.100", false);
                }
                memcpy(mut, req, len);
                mut[pos] = 0xFF;
                sw_run(mut, len, 512, names[n], 1, "192.0.2.100", pos & 1);
            }
        }
    }
    /* header-flag / opcode / class matrix */
    for (int op = 0; op < 16; op++) {
        for (int fl = 0; fl < 4; fl++) {
            uint8_t f2 = (uint8_t)((op << 3) | (fl & 1 ? 0x80 : 0) | (fl & 2 ? 0x02 : 0) | 0x01);
            for (int rc = 0; rc < 3; rc++) {
                uint8_t f3 = (uint8_t)((rc == 1 ? 0x20 : 0) | (rc == 2 ? 0x10 : 0));
                uint16_t classes[] = { 1, 3, 4, 254, 255 };
                for (size_t c = 0; c < NELEM(classes); c++) {
                    size_t len = sw_build(req, 0x1234, f2, f3, "www.example.", 1, classes[c], Q_EDNS);
                    sw_run(req, len, 512, "www.example.", 1, "192.0.2.100", false);
                }
            }
        }
    }
}

static const char *SW_CONFIGS[] = {
    "options { directory \".\"; };\n"
    "view \"default\" { match-clients { any; };\n"
    "  zone \"example.\" { type master; file \"x\"; };\n"
    "  zone \"n3.example.\" { type master; file \"y\"; };\n"
    "  zone \"other.test.\" { type master; file \"z\"; };\n"
    "  zone \"geo.test.\" { type master; file \"g\"; };\n"
    "  zone \"nosoa.test.\" { type master; file \"s\"; };\n};\n",

    "options { directory \".\"; minimal-responses yes; minimal-any yes; additional-from-auth no;\n"
    "  send-extended-errors yes; nsid \"sweep-ns\"; max-mqtypes 2; rfc10029-mqtype yes;\n"
    "  ecs-enable yes; ecs-trusted-resolvers { 127.0.0.1; ::1; }; serve-stale yes;\n"
    "  tcp-connection-reuse yes; tcp-idle-timeout 30000; minimal-any-ttl 60;\n"
    "  cookie-secret \"000102030405060708090a0b0c0d0e0f\";\n"
    "  cookie-secret \"f0e0d0c0b0a090807060504030201000\"; };\n"
    "view \"default\" { match-clients { any; };\n"
    "  zone \"example.\" { type master; file \"x\"; };\n"
    "  zone \"n3.example.\" { type master; file \"y\"; };\n"
    "  zone \"other.test.\" { type master; file \"z\"; };\n"
    "  zone \"geo.test.\" { type master; file \"g\"; };\n"
    "  zone \"nosoa.test.\" { type master; file \"s\"; };\n};\n",

    "options { directory \".\"; minimal-responses no; minimal-any no; additional-from-auth in-domain;\n"
    "  rfc10029-mqtype yes; max-mqtypes 8; ecs-enable yes; ecs-trusted-resolvers { any; };\n"
    "  wire-cache-max-records 1000; nsid \"n\"; tcp-connection-reuse yes; };\n"
    "view \"default\" { match-clients { any; };\n"
    "  zone \"example.\" { type master; file \"x\"; additional-from-auth yes; };\n"
    "  zone \"n3.example.\" { type master; file \"y\"; additional-from-auth in-domain; };\n"
    "  zone \"other.test.\" { type master; file \"z\"; additional-from-auth no; };\n"
    "  zone \"geo.test.\" { type master; file \"g\"; additional-from-auth in-domain; disable-auto-tc-flag yes; };\n"
    "  zone \"nosoa.test.\" { type master; file \"s\"; };\n};\n",
};

static void sw_setup_all(const char *conf, bool optout) {
    sw_teardown();
    g_sw.cfg = sw_conf(conf);
    sw_add_zone("example.", ZONE_EXAMPLE);
    char *n3 = make_nsec3_zone(optout);
    sw_add_zone("n3.example.", n3);
    free(n3);
    sw_add_zone("other.test.", ZONE_OTHER);
    sw_add_zone("geo.test.", ZONE_GEO);
    sw_add_zone("nosoa.test.", ZONE_NOSOA);
    sw_finish_view();
}

static void sw_prelink_and_cache(additional_from_auth_t policy) {
    for (int i = 0; i < g_sw.zone_count; i++) {
        prelink_zone_additional_glue(&g_sw.arena[i], g_sw.entry[i].domain, &g_sw.snap, &g_sw.view, policy);
        build_zone_response_cache(&g_sw.arena[i], g_sw.cfg, g_sw.entry[i].domain);
    }
}

static void test_sweep_query_engine(void) {
    printf("[TEST] Sweep: query matrix x configs, truncation sweep, mutation sweep...\n");
    for (size_t c = 0; c < NELEM(SW_CONFIGS); c++) {
        sw_setup_all(SW_CONFIGS[c], c == 1);
        if (c == 2) sw_prelink_and_cache(ADDITIONAL_AUTH_YES);
        sw_matrix(c == 0);
        if (c == 0) {
            sw_truncation_sweep();
            sw_mutation_sweep();
            /* same zones, glue pre-linked with each policy, re-run the truncation sweep */
            sw_prelink_and_cache(ADDITIONAL_AUTH_IN_DOMAIN);
            sw_truncation_sweep();
        }
    }
    sw_teardown();
    printf("  -> %lu engine invocations passed invariants.\n", g_calls);
}


/* ===========================================================================
 * Fake upstream forwarder (UDP + TCP on 127.0.0.1) driven by a scenario id.
 * ======================================================================== */
enum { FW_OK, FW_SILENT, FW_BADID, FW_NOQR, FW_BADQ, FW_TC_TCPOK, FW_TC_TCPFAIL,
       FW_TC_TCPBADID, FW_HUGE, FW_SHORT, FW_TC_TCPZERO, FW_TC_TCPCLOSE, FW_TC_TCPBIG };
static volatile int g_fw_scn;
static volatile int g_fw_stop;
static int g_fw_udp = -1, g_fw_tcp = -1, g_fw_port;

static size_t fw_answer(const uint8_t *q, size_t qlen, uint8_t *out, size_t pad) {
    memcpy(out, q, qlen);
    out[2] |= 0x80;
    if (pad) {
        /* one big TXT answer made of 255-byte strings */
        size_t off = qlen;
        out[7] = 1;
        out[off++] = 0xC0; out[off++] = 12; out[off++] = 0; out[off++] = 16;
        out[off++] = 0; out[off++] = 1; out[off++] = 0; out[off++] = 0; out[off++] = 0; out[off++] = 60;
        size_t rdl = pad;
        out[off++] = (uint8_t)(rdl >> 8); out[off++] = (uint8_t)rdl;
        size_t left = rdl;
        while (left) { size_t c = left > 256 ? 256 : left; out[off] = (uint8_t)(c - 1); memset(out + off + 1, 'x', c - 1); off += c; left -= c; }
        return off;
    }
    return qlen;
}

static void *fw_thread(void *arg) {
    (void)arg;
    uint8_t buf[4096], out[70000];
    while (!g_fw_stop) {
        struct pollfd p[2] = { { g_fw_udp, POLLIN, 0 }, { g_fw_tcp, POLLIN, 0 } };
        if (poll(p, 2, 50) <= 0) continue;
        if (p[0].revents & POLLIN) {
            struct sockaddr_storage from; socklen_t fl = sizeof(from);
            ssize_t n = recvfrom(g_fw_udp, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
            if (n < 12) continue;
            int scn = g_fw_scn;
            size_t olen = fw_answer(buf, (size_t)n, out, scn == FW_HUGE ? 1400 : 0);
            switch (scn) {
            case FW_SILENT: continue;
            case FW_BADID: out[0] ^= 0xFF; break;
            case FW_NOQR: out[2] &= 0x7F; break;
            case FW_BADQ: out[13] ^= 0x01; break;
            case FW_SHORT: olen = 6; break;
            case FW_TC_TCPOK: case FW_TC_TCPFAIL: case FW_TC_TCPBADID: case FW_TC_TCPZERO:
            case FW_TC_TCPCLOSE: case FW_TC_TCPBIG: out[2] |= 0x02; break;
            default: break;
            }
            sendto(g_fw_udp, out, olen, 0, (struct sockaddr *)&from, fl);
        }
        if (p[1].revents & POLLIN) {
            int c = accept(g_fw_tcp, NULL, NULL);
            if (c < 0) continue;
            int scn = g_fw_scn;
            if (scn == FW_TC_TCPCLOSE) { close(c); continue; }
            uint8_t lp[2];
            if (read_all_timeout(c, lp, 2, 1000) != 2) { close(c); continue; }
            size_t ql = ((size_t)lp[0] << 8) | lp[1];
            if (ql > sizeof(buf) || read_all_timeout(c, buf, ql, 1000) != (ssize_t)ql) { close(c); continue; }
            size_t olen = fw_answer(buf, ql, out, scn == FW_TC_TCPBIG ? 3000 : 600);
            if (scn == FW_TC_TCPBADID) out[0] ^= 0xFF;
            if (scn == FW_TC_TCPZERO) olen = 0;
            uint8_t hl[2] = { (uint8_t)(olen >> 8), (uint8_t)olen };
            if (scn != FW_TC_TCPFAIL) {
                write_all_timeout(c, hl, 2, 1000);
                if (olen) write_all_timeout(c, out, olen, 1000);
            }
            close(c);
        }
    }
    return NULL;
}

static pthread_t fw_start(void) {
    struct sockaddr_in a = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    g_fw_udp = socket(AF_INET, SOCK_DGRAM, 0);
    assert(g_fw_udp >= 0);
    assert(bind(g_fw_udp, (struct sockaddr *)&a, sizeof(a)) == 0);
    socklen_t al = sizeof(a);
    getsockname(g_fw_udp, (struct sockaddr *)&a, &al);
    g_fw_port = ntohs(a.sin_port);
    g_fw_tcp = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_fw_tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    assert(bind(g_fw_tcp, (struct sockaddr *)&a, sizeof(a)) == 0);
    assert(listen(g_fw_tcp, 16) == 0);
    g_fw_stop = 0;
    pthread_t t;
    pthread_create(&t, NULL, fw_thread, NULL);
    return t;
}

static void test_forward_zone_scenarios(void) {
    printf("[TEST] Sweep: forward zone against a scripted upstream...\n");
    pthread_t t = fw_start();
    char conf[2048];
    snprintf(conf, sizeof(conf),
        "options { directory \".\"; };\n"
        "view \"default\" { match-clients { any; };\n"
        "  zone \"fwd.test.\" { type forward; forwarders { 127.0.0.1 port %d; }; forward-timeout 300; };\n"
        "  zone \"fwd2.test.\" { type forward; forwarders { not-an-ip; 127.0.0.1 port 1; 127.0.0.1 port %d; }; forward-timeout 400; };\n"
        "  zone \"example.\" { type master; file \"x\"; };\n"
        "};\n", g_fw_port, g_fw_port);
    sw_teardown();
    g_sw.cfg = sw_conf(conf);
    sw_add_zone("example.", ZONE_EXAMPLE);
    sw_add_zone("fwd.test.", "$ORIGIN fwd.test.\n@ 60 IN SOA a. b. 1 2 3 4 5\n@ 60 IN NS ns.fwd.test.\n");
    sw_add_zone("fwd2.test.", "$ORIGIN fwd2.test.\n@ 60 IN SOA a. b. 1 2 3 4 5\n@ 60 IN NS ns.fwd2.test.\n");
    sw_finish_view();
    zone_config_t *z1 = find_zone_config_in_view(g_sw.cfg, "default", "fwd.test.");
    zone_config_t *z2 = find_zone_config_in_view(g_sw.cfg, "default", "fwd2.test.");
    assert(z1 && z2);

    uint8_t req[512], res[4096];
    const char *names[] = { "www.fwd.test.", "www.fwd2.test." };
    zone_config_t *zs[] = { z1, z2 };
    for (int scn = FW_OK; scn <= FW_TC_TCPBIG; scn++) {
        g_fw_scn = scn;
        for (int zi = 0; zi < 2; zi++) {
            size_t len = sw_build(req, (uint16_t)(0x6000 + scn), 0x01, 0, names[zi], 1, 1, Q_EDNS);
            size_t lims[] = { 12, 20, 100, 512, 4096 };
            for (size_t l = 0; l < NELEM(lims); l++) {
                if (scn == FW_SILENT && l > 0) break;         /* each silent round costs a timeout */
                int n = dispatch_forward_zone(zs[zi], req, len, res, lims[l]);
                assert(n >= 0 && (size_t)n <= lims[l]);
            }
            /* also via the full engine path */
            if (scn == FW_OK || scn == FW_HUGE)
                sw_run(req, len, 512, names[zi], 1, "192.0.2.1", false);
        }
    }
    /* invalid inputs */
    assert(dispatch_forward_zone(z1, req, 5, res, sizeof(res)) == 0);
    int saved = z1->forwarders_count; z1->forwarders_count = 0;
    size_t len = sw_build(req, 1, 1, 0, "www.fwd.test.", 1, 1, 0);
    assert(dispatch_forward_zone(z1, req, len, res, sizeof(res)) > 0);
    z1->forwarders_count = saved;
    g_broker_fail = 1;
    assert(dispatch_forward_zone(z1, req, len, res, sizeof(res)) > 0);
    struct sockaddr_storage ss; size_t sl = resolve_ip_port_to_sockaddr("127.0.0.1", g_fw_port, &ss);
    assert(forward_via_tcp(&ss, sl, req, len, res, sizeof(res), 100) == -1);
    g_broker_fail = 0;
    assert(forward_via_tcp(NULL, sl, req, len, res, sizeof(res), 100) == -1);
    g_fw_scn = FW_TC_TCPOK;
    assert(forward_via_tcp(&ss, sl, req, len, res, 20, 500) == -1);     /* response larger than cap */
    assert(forward_via_tcp(&ss, sl, req, len, res, sizeof(res), 500) > 12);
    /* question_section_matches edge cases */
    uint8_t a[64], b[64];
    size_t al = sw_build(a, 1, 0, 0, "Www.Fwd.Test.", 1, 1, 0);
    size_t bl = sw_build(b, 1, 0, 0, "www.fwd.test.", 1, 1, 0);
    assert(question_section_matches(a, al, b, bl));
    assert(!question_section_matches(a, 12, b, bl));
    assert(!question_section_matches(a, al - 1, b, bl));
    b[bl - 1] = 3; assert(!question_section_matches(a, al, b, bl));
    b[12] = 2; assert(!question_section_matches(a, al, b, bl));
    b[12] = 70; a[12] = 70; assert(!question_section_matches(a, al, b, bl));

    g_fw_stop = 1;
    pthread_join(t, NULL);
    close(g_fw_udp); close(g_fw_tcp);
    sw_teardown();
    printf("  -> forward zone scenarios passed.\n");
}

/* ===========================================================================
 * Program-zone plugin emulated with pipes + a thread playing the plugin.
 * ======================================================================== */
enum { PG_OK, PG_ZERO, PG_BIG, PG_SHORTBODY, PG_NOREPLY, PG_OVERSIZE, PG_OVERSIZE_TRUNCBODY,
       PG_OVERSIZE_BADQ, PG_CLOSE };
typedef struct { int in_rd, out_wr; int scn; int rounds; } pg_ctx_t;

static void *pg_thread(void *arg) {
    pg_ctx_t *c = arg;
    uint8_t buf[4096], out[8192];
    for (int r = 0; r < c->rounds; r++) {
        /* header line */
        size_t hl = 0; uint8_t ch;
        while (hl < 100 && read(c->in_rd, &ch, 1) == 1) { hl++; if (ch == '\n') break; }
        uint8_t lp[2];
        if (read_all_timeout(c->in_rd, lp, 2, 2000) != 2) break;
        size_t ql = ((size_t)lp[0] << 8) | lp[1];
        if (read_all_timeout(c->in_rd, buf, ql, 2000) != (ssize_t)ql) break;
        size_t olen = fw_answer(buf, ql, out, 0);
        uint8_t rl[2];
        switch (c->scn) {
        case PG_OK: break;
        case PG_ZERO: olen = 0; break;
        case PG_BIG: case PG_OVERSIZE: case PG_OVERSIZE_TRUNCBODY: case PG_OVERSIZE_BADQ:
            olen = fw_answer(buf, ql, out, 1500);
            if (c->scn == PG_OVERSIZE_BADQ) out[12] = 0x3F;
            break;
        case PG_SHORTBODY: break;
        case PG_NOREPLY: continue;
        case PG_CLOSE: close(c->out_wr); c->out_wr = -1; return NULL;
        }
        rl[0] = (uint8_t)(olen >> 8); rl[1] = (uint8_t)olen;
        write_all_timeout(c->out_wr, rl, 2, 1000);
        size_t send_len = olen;
        if (c->scn == PG_SHORTBODY || c->scn == PG_OVERSIZE_TRUNCBODY) send_len = olen / 2;
        if (send_len) write_all_timeout(c->out_wr, out, send_len, 1000);
    }
    return NULL;
}

static void pg_run(int scn, bool disable_tc, size_t max_res, int rounds, uint32_t max_fail) {
    int in_p[2], out_p[2];
    assert(pipe(in_p) == 0 && pipe(out_p) == 0);
    static program_plugin_t plug;
    memset(&plug, 0, sizeof(plug));
    strcpy(plug.domain, "prog.test.");
    plug.pid = -1;
    plug.stdin_fd = in_p[1];
    plug.stdout_fd = out_p[0];
    pthread_mutex_init(&plug.lock, NULL);
    plug.timeout_ms = 150;
    plug.max_failures = max_fail;
    plug.disable_auto_tc_flag = disable_tc;
    g_program_plugins = &plug;
    g_program_plugins_count = 1;
    pg_ctx_t c = { in_p[0], out_p[1], scn, rounds };
    pthread_t t;
    pthread_create(&t, NULL, pg_thread, &c);
    uint8_t req[512], res[8192];
    for (int r = 0; r < rounds; r++) {
        size_t len = sw_build(req, (uint16_t)(0x7100 + r), 0x01, 0, "a.prog.test.", 1, 1, 0);
        int n = dispatch_to_program_zone("prog.test.", req, len, res, max_res, r & 1 ? NULL : "192.0.2.9", r & 1);
        assert(n >= 0);
    }
    close(in_p[1]);
    pthread_join(t, NULL);
    close(in_p[0]); close(out_p[0]); if (c.out_wr >= 0) close(c.out_wr);
    pthread_mutex_destroy(&plug.lock);
    g_program_plugins = NULL;
    g_program_plugins_count = 0;
}

static void test_program_zone_emulated(void) {
    printf("[TEST] Sweep: program-zone plugin protocol edge cases...\n");
    pg_run(PG_OK, false, 512, 2, 3);
    pg_run(PG_OK, true, 512, 1, 3);
    pg_run(PG_ZERO, false, 512, 1, 3);
    pg_run(PG_BIG, true, 512, 1, 3);                 /* disable-auto-tc: full length accepted */
    pg_run(PG_SHORTBODY, true, 512, 1, 3);
    pg_run(PG_SHORTBODY, false, 512, 1, 3);
    pg_run(PG_OVERSIZE, false, 512, 1, 3);           /* truncated with TC=1, rest drained */
    pg_run(PG_OVERSIZE, false, 20, 1, 3);            /* first chunk shorter than the question */
    pg_run(PG_OVERSIZE_BADQ, false, 40, 1, 3);
    pg_run(PG_OVERSIZE_TRUNCBODY, false, 512, 1, 3); /* drain fails */
    pg_run(PG_OVERSIZE_TRUNCBODY, false, 100, 1, 3);
    pg_run(PG_NOREPLY, false, 512, 2, 2);            /* timeouts -> marked dead */
    pg_run(PG_CLOSE, false, 512, 1, 1);
    /* unknown zone / dead plugin / helpers */
    uint8_t req[512], res[512];
    size_t len = sw_build(req, 1, 1, 0, "a.prog.test.", 1, 1, 0);
    assert(dispatch_to_program_zone("none.test.", req, len, res, sizeof(res), NULL, false) > 0);
    assert(find_program_plugin(NULL) == NULL);
    assert(build_synthetic_servfail(req, 5, res, sizeof(res)) == 0);
    assert(build_synthetic_servfail(req, len, res, 5) == 0);
    assert(build_synthetic_servfail(req, len, res, 16) == 16 && res[5] == 0);
    assert(remaining_ms(monotonic_ms() - 10) == 0);
    assert(remaining_ms(monotonic_ms() + 100000) > 0);
    assert(write_all_timeout(-1, req, 4, 10) == -1);
    assert(read_all_timeout(-1, res, 4, 10) == -1);
    assert(write_all_timeout(1, req, 4, 0) == -1);
    int p[2]; assert(pipe(p) == 0);
    close(p[1]);
    assert(read_all_timeout(p[0], res, 4, 50) == -1);   /* EOF */
    close(p[0]);
    assert(pipe(p) == 0);
    close(p[0]);
    signal(SIGPIPE, SIG_IGN);
    assert(write_all_timeout(p[1], req, 4, 50) == -1);  /* EPIPE / POLLERR */
    close(p[1]);
    zone_config_t z; memset(&z, 0, sizeof(z));
    char *args[] = { "a", "b" };
    z.program_path = "/bin/true"; z.program_args = args; z.program_args_count = 2;
    char fp[64];
    compute_program_zone_fingerprint(&z, fp, sizeof(fp));
    compute_program_zone_fingerprint(&z, fp, 20);
    printf("  -> program-zone plugin emulation passed.\n");
}

/* ===========================================================================
 * Direct calls of the engine's helpers with degenerate arguments.
 * ======================================================================== */
static void test_engine_helper_edges(void) {
    printf("[TEST] Sweep: engine helper edge cases...\n");
    char out[128];
    uint8_t wire[300];
    const uint8_t salt[1] = { 1 };
    assert(name_to_canonical_wire(NULL, wire, sizeof(wire)) == 0);
    assert(name_to_canonical_wire("a.", wire, 0) == 0);
    assert(name_to_canonical_wire("abc.def.", wire, 4) == 0);
    assert(name_to_canonical_wire("abc", wire, 4) == 0);
    assert(name_to_canonical_wire("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", wire, sizeof(wire)) == 0);
    assert(name_to_canonical_wire("A..b", wire, sizeof(wire)) > 0);
    assert(compute_nsec3_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.", 1, 0, salt, 1, out, sizeof(out)) == false);
    assert(compute_nsec3_hash("a.", 1, 0, salt, 1, out, 0) == true);
    assert(compute_nsec3_hash("a.", 1, 0, salt, 1, out, 3) == true);
    assert(nsec3_covers_hash("a", NULL, "b") == false);
    assert(nsec3_covers_hash("a", "b", NULL) == false);
    assert(find_next_closer_name(NULL, "a.", out, sizeof(out)) == false);
    assert(find_next_closer_name("a.b.", NULL, out, sizeof(out)) == false);
    assert(find_next_closer_name("a.b.", "b.", NULL, sizeof(out)) == false);
    assert(find_next_closer_name("a.b.", "b.", out, 0) == false);
    assert(find_next_closer_name("xa.b.", "a.b.", out, sizeof(out)) == false);
    assert(find_next_closer_name("a.x.c.", "b.c.", out, sizeof(out)) == false);
    assert(find_next_closer_name("longlabel.b.", "b.", out, 4) == false);
    assert(find_next_closer_name("q.r.b", "b", out, sizeof(out)) == true && strcmp(out, "r.b") == 0);

    /* arena helpers on empty / incomplete zones */
    zone_arena_t z; memset(&z, 0, sizeof(z)); zone_arena_init(&z);
    assert(find_matching_nsec3(NULL, "x", "a.") == NULL);
    assert(find_matching_nsec3(&z, NULL, "a.") == NULL);
    assert(find_matching_nsec3(&z, "x", NULL) == NULL);
    assert(find_matching_nsec3(&z, "x", "a.") == NULL);
    assert(find_covering_nsec3(NULL, "x") == NULL);
    assert(find_covering_nsec3(&z, NULL) == NULL);
    assert(find_covering_nsec3(&z, "x") == NULL);
    assert(name_exists_in_zone(NULL, "a.", "\0\0", NULL, NULL) == false);
    assert(name_exists_in_zone(&z, NULL, "\0\0", NULL, NULL) == false);
    assert(name_exists_in_zone(&z, "a.", "\0\0", NULL, NULL) == false);
    const char *apx = "a.";
    assert(find_closest_encloser(NULL, "a.", apx, "\0\0", NULL, NULL) == apx);
    assert(find_closest_encloser(&z, NULL, apx, "\0\0", NULL, NULL) == apx);
    assert(find_closest_encloser(&z, "a.", NULL, "\0\0", NULL, NULL) == NULL);
    assert(find_closest_encloser(&z, "a.", apx, "\0\0", NULL, NULL) == apx);
    assert(find_covering_nsec(&z, "a.") == NULL);
    uint16_t off = 12, cnt = 0;
    compress_ctx_t cc; compress_ctx_init(&cc);
    uint8_t res[512];
    assert(find_delegation(NULL, "a.", 0, "a.", res, sizeof(res), &off, &cc, &cnt, &cnt, false,
                           "\0\0", NULL, NULL, ADDITIONAL_AUTH_YES, NULL, false) == false);
    assert(find_delegation(&z, "a.", 0, "a.", res, sizeof(res), &off, &cc, &cnt, &cnt, false,
                           "\0\0", NULL, NULL, ADDITIONAL_AUTH_YES, NULL, false) == false);
    assert(append_glue_records(NULL, "a.", "a.", res, sizeof(res), &off, &cc, &cnt, "\0\0", NULL, NULL, ADDITIONAL_AUTH_YES, NULL));
    assert(append_glue_records(&z, NULL, "a.", res, sizeof(res), &off, &cc, &cnt, "\0\0", NULL, NULL, ADDITIONAL_AUTH_YES, NULL));
    assert(append_glue_records(&z, "a.", "a.", res, sizeof(res), &off, &cc, &cnt, "\0\0", NULL, NULL, ADDITIONAL_AUTH_NO, NULL));

    /* nsec_covers_name with malformed records */
    dns_record_t r; memset(&r, 0, sizeof(r));
    assert(nsec_covers_name(NULL, "a.") == false);
    assert(nsec_covers_name(&r, "a.") == false);
    r.type_code = 47;
    assert(nsec_covers_name(&r, "a.") == false);
    r.rdata[0] = "c.example."; r.rdata[1] = "A"; r.rdata_count = 2;
    assert(nsec_covers_name(&r, "a.") == false);
    r.name = "a.example.";
    assert(nsec_covers_name(&r, NULL) == false);
    assert(nsec_covers_name(&r, "b.example.") == true);
    r.rdata[0] = "example.";   /* last NSEC in the chain (wrap-around) */
    assert(nsec_covers_name(&r, "z.example.") == true);

    /* collect_additional_rr_glue variants */
    const char *gt[16]; int gc = 0;
    collect_additional_rr_glue(NULL, gt, &gc, false);
    collect_additional_rr_glue(&r, NULL, &gc, false);
    collect_additional_rr_glue(&r, gt, NULL, false);
    collect_additional_rr_glue(&r, gt, &gc, true);
    dns_record_t m; memset(&m, 0, sizeof(m)); m.type_code = 15; m.rdata[0] = "10"; m.rdata[1] = ""; m.rdata_count = 2;
    char **mx = m.rdata;
    collect_additional_rr_glue(&m, gt, &gc, false);            /* empty target */
    mx[1] = "mail.example.";
    for (int i = 0; i < 20; i++) collect_additional_rr_glue(&m, gt, &gc, false);  /* dedupe */
    char names[20][32];
    for (int i = 0; i < 20; i++) { snprintf(names[i], sizeof(names[i]), "h%d.example.", i); mx[1] = names[i]; collect_additional_rr_glue(&m, gt, &gc, false); }
    assert(gc == 16);
    m.rdata_count = 1; gc = 0; collect_additional_rr_glue(&m, gt, &gc, false); assert(gc == 0);
    m.type_code = 33; collect_additional_rr_glue(&m, gt, &gc, false);
    m.type_code = 2; m.rdata_count = 0; collect_additional_rr_glue(&m, gt, &gc, false);
    m.type_code = 1; collect_additional_rr_glue(&m, gt, &gc, false);

    /* attach_nsec3_record dedupe + overflow */
    dns_record_t *att[8] = {0}; int ac = 0;
    assert(attach_nsec3_record(&z, NULL, res, sizeof(res), &off, &cc, &cnt, att, &ac));
    zone_arena_destroy(&z);

    /* hex_to_bytes / record observatory */
    uint8_t hb[4];
    assert(hex_to_bytes(NULL, hb, 4) == 0);
    assert(hex_to_bytes("-", hb, 4) == 0);
    assert(hex_to_bytes("", hb, 4) == 0);
    assert(hex_to_bytes("0102030405", hb, 4) == 4);
    assert(hex_to_bytes("abc", hb, 4) == 1);
    zone_db_entry_t e; memset(&e, 0, sizeof(e));
    for (int rc = 0; rc < 6; rc++) { record_observatory_response(&e, (uint8_t)rc, 0); record_observatory_response(&e, (uint8_t)rc, 1); }
    record_observatory_response(NULL, 0, 0);
    printf("  -> engine helper edge cases passed.\n");
}

/* ===========================================================================
 * Wire-format sweeps: every RR type is serialized under every buffer limit,
 * re-parsed from wire at every truncation length and with every byte mutated.
 * ======================================================================== */
static const char *RR_LINES[] = {
    "IN A 192.0.2.1", "IN AAAA 2001:db8::1", "IN AFSDB 1 srv.example.",
    "IN APL 1:192.168.0.0/24 !2:2001:db8::/32 1:0.0.0.0/0 2:::/0", "IN AVC \"app-name:x\"",
    "IN AMTRELAY 10 0 1 192.0.2.2", "IN AMTRELAY 10 1 2 2001:db8::2",
    "IN AMTRELAY 10 0 3 relay.example.", "IN AMTRELAY 10 0 0 .",
    "IN CAA 0 issue \"letsencrypt.org\"", "IN CAA 128 iodef \"mailto:a@example\"",
    "IN CDS 12345 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN CERT 1 12345 8 AQIDBAUG", "IN CERT PKIX 1 RSASHA256 AQIDBAUG", "IN CNAME target.example.", "IN CSYNC 66 3 A NS AAAA",
    "IN DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
    "IN DLV 12345 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN DNAME target.example.",
    "IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN DS 12345 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN DSYNC CDS NOTIFY 5300 scanner.example.", "IN EUI48 00-00-5e-00-53-2a",
    "IN EUI64 00-00-5e-ef-10-00-00-2a", "IN GPOS -32.6882 116.8652 10.0", "IN HINFO \"PC\" \"Linux\"",
    "IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs.example. rvs2.example.",
    "IN HTTPS 1 . alpn=h2", "IN HTTPS 0 svc.example.",
    "IN SVCB 1 svc.example. mandatory=alpn alpn=h2,h3 no-default-alpn port=8443 ipv4hint=192.0.2.1,192.0.2.2 ech=AQIDBAUG ipv6hint=2001:db8::1 key65000=abc",
    "IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 2 2 2001:db8::38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 3 2 gw.example. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN ISDN \"150862028003217\" \"004\"", "IN ISDN \"150862028003217\"",
    "IN KEY 256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN KX 10 kx.example.", "IN L32 10 10.1.2.0", "IN L64 10 2001:0db8:1140:1000", "IN LP 10 lp.example.",
    "IN NID 10 0014:4fff:ff20:ee64", "IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
    "IN LOC 1 S 2 W 0m", "IN LOC 42 21 54 N 71 06 18 W -24m 30m",
    "IN MX 10 mail.example.", "IN MB mb.example.", "IN MD md.example.", "IN MF mf.example.",
    "IN MG mg.example.", "IN MR mr.example.", "IN MINFO rm.example. em.example.",
    "IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"!^.*$!sip:x@example.com!\" _sip._udp.example.",
    "IN NS ns2.example.", "IN NSAP 0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00",
    "IN NSAP-PTR ptr.example.", "IN NSEC next.example. A RRSIG NSEC TYPE1234 CAA",
    "IN NSEC3 1 0 10 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG",
    "IN NSEC3 1 1 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A", "IN NSEC3PARAM 1 0 10 aabbccdd",
    "IN NSEC3PARAM 1 0 0 -", "IN NINFO \"text\"", "IN OPENPGPKEY AQIDBAUG", "IN PTR ptr.example.",
    "IN PX 10 a.example. b.example.", "IN RP mbox.example. txt.example.", "IN RT 10 rt.example.",
    "IN RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN SMIMEA 3 1 1 AABBCCDDEEFF00112233445566778899", "IN TLSA 3 1 1 AABBCCDDEEFF00112233445566778899",
    "IN SSHFP 1 1 AABBCCDDEEFF00112233445566778899AABBCCDD", "IN SPF \"v=spf1 -all\"",
    "IN TXT \"text\" \"second\" \"\"", "IN URI 10 1 \"ftp://ftp.example.com/\"", "IN SRV 10 60 5060 sip.example.",
    "IN WKS 192.0.2.1 6 25 80", "IN WKS 192.0.2.1 UDP 53 161", "IN X25 \"311061700956\"",
    "IN ZONEMD 2018031500 1 1 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN NXT next.example. A", "IN SINK 1 1 AQIDBAUG", "IN TALINK a.example. b.example.",
    "IN SIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN TYPE65280 \\# 4 DEADBEEF", "IN A \\# 4 C0000201", "IN TA 12345 13 2 AABBCCDD",
    "IN EID \\# 2 0102", "IN NIMLOC \\# 2 0102", "IN DOA 1 2 3 \"text/plain\" AQIDBAUG",
    "IN BRID \\# 2 0102", "IN HHIT \\# 2 0102", "IN NULL \\# 2 0102", "IN TYPE9999 \\# 0",
    "IN A6 0 2001:db8::1", "IN A6 64 ::1 pfx.example.", "IN ATMA +358400123456", "IN ATMA 39246f00e7c9",
    "IN RKEY 0 3 5 AQIDBAUG", "IN SOA ns.example. host.example. 1 2 3 4 5",
    "CH TXT \"chaos\"", "HS A 192.0.2.1", "IN GPOS 1 2 3", "IN HINFO \"only-cpu\" \"\"",
};

static void rr_parse_sweep(const uint8_t *pkt, size_t len) {
    zone_arena_t a; memset(&a, 0, sizeof(a)); zone_arena_init(&a);
    dns_record_t r; uint16_t t;
    for (size_t cut = 12; cut <= len; cut++) {
        size_t off = 12; memset(&r, 0, sizeof(r));
        (void)parse_resource_record(pkt, cut, &off, &a, &r, &t);
    }
    uint8_t m[2048];
    for (size_t pos = 12; pos < len; pos++) {
        memcpy(m, pkt, len);
        m[pos] ^= 0xFF;
        size_t off = 12; memset(&r, 0, sizeof(r));
        (void)parse_resource_record(m, len, &off, &a, &r, &t);
        m[pos] = 0;
        off = 12;
        (void)parse_resource_record(m, len, &off, &a, &r, &t);
    }
    zone_arena_destroy(&a);
}

static void test_wire_rr_sweep(void) {
    printf("[TEST] Sweep: serialize/parse every RR type under every buffer limit...\n");
    size_t cap = 64 * 1024;
    char *zt = malloc(cap); assert(zt);
    size_t o = (size_t)snprintf(zt, cap, "$ORIGIN example.\n$TTL 300\n");
    for (size_t i = 0; i < NELEM(RR_LINES); i++)
        o += (size_t)snprintf(zt + o, cap - o, "r%zu.sub.example. 300 %s\n", i, RR_LINES[i]);
    zone_arena_t z; memset(&z, 0, sizeof(z)); zone_arena_init(&z);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.", .is_standalone_mode = true, .err_out = &err };
    char *buf = arena_strdup(&z, zt);
    (void)parse_zone_fast(buf, strlen(buf), &z, &ctx);
    free(zt);
    printf("  (parsed %zu records)\n", z.count);
    static uint8_t pkt[8192];
    compress_ctx_t cc;
    size_t total = 0;
    static const char *garbage[] = { "", "x", "-1", "99999999999", "65536", "256", "0", "1.2.3",
        "zz:zz", "=", "\"unterminated", "300.1.1.1", "AQIDBAUG", "@@@@", "0x", "N", "E",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "a.very.long.label.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.",
        "alpn=", "port=99999", "key99999=1", "mandatory=bogus", "ipv4hint=1.2.3.x", "ipv6hint=zz", "ech=@@",
        "\\# 2 01", "\\# 1 0102", "1:1.2.3.4/33", "3:1.2.3.4/8", "!1:1.2.3.0/24", "RSASHA1", "UNKNOWNALG", "TYPE70000", "BOGUS",
        "20301301000000", "2030010100000", "1m", "99999999m", "91", "181", "60.5", "S", "W", "-1m" };
    uint8_t scratch[4096];
    for (size_t i = 0; i < z.count; i++) {
        dns_record_t *rec = &z.records[i];
        /* uncached path first (text RDATA converted on the fly) */
        for (size_t lim = 0; lim <= 300; lim += 1) {
            uint16_t off = 12; compress_ctx_init(&cc);
            (void)serialize_dns_record(pkt, lim, &off, rec, &cc, NULL, 0xFFFFFFFF);
        }
        /* malformed RDATA fields and missing fields */
        for (int f = 0; f < rec->rdata_count && f < 12; f++) {
            for (size_t g = 0; g < NELEM(garbage); g++) {
                dns_record_t copy = *rec;
                copy.rdata[f] = (char *)garbage[g];
                copy.is_cached = false;
                uint16_t off = 12; compress_ctx_init(&cc);
                (void)serialize_dns_record(scratch, sizeof(scratch), &off, &copy, &cc, NULL, 0xFFFFFFFF);
                off = 12;
                (void)serialize_dns_record(scratch, 40, &off, &copy, &cc, NULL, 0xFFFFFFFF);
            }
        }
        for (int cnt = 0; cnt < rec->rdata_count; cnt++) {
            dns_record_t copy = *rec; copy.rdata_count = cnt; copy.is_cached = false;
            uint16_t off = 12; compress_ctx_init(&cc);
            (void)serialize_dns_record(scratch, sizeof(scratch), &off, &copy, &cc, NULL, 0xFFFFFFFF);
        }
        {   /* class strings / TTL strings */
            const char *cls[] = { "CH", "NONE", "ANY", "HS", "IN" };
            for (size_t c = 0; c < NELEM(cls); c++) {
                dns_record_t copy = *rec; copy.class_val = 0; copy.class_str = (char *)cls[c];
                copy.ttl_value = 0; copy.ttl = c & 1 ? "1h" : "4294967295";
                uint16_t off = 12; compress_ctx_init(&cc);
                (void)serialize_dns_record(scratch, sizeof(scratch), &off, &copy, &cc, NULL, 0xFFFFFFFF);
            }
        }
        dns_record_preparse_cache(&z, rec);
        for (size_t lim = 0; lim <= 700; lim++) {
            uint16_t off = 12; compress_ctx_init(&cc);
            (void)serialize_dns_record(pkt, lim, &off, rec, &cc, NULL, 0xFFFFFFFF);
        }
        for (size_t lim = 12; lim <= 400; lim++) {
            uint16_t off = 12; compress_ctx_init(&cc);
            (void)serialize_dns_record(pkt, lim, &off, rec, &cc, "owner.override.example.", 77);
        }
        memset(pkt, 0, 12);
        uint16_t off = 12; compress_ctx_init(&cc);
        int rc = serialize_dns_record(pkt, sizeof(pkt), &off, rec, &cc, NULL, 0xFFFFFFFF);
        if (rc >= 0) {
            uint16_t first_end = off;
            (void)serialize_dns_record(pkt, sizeof(pkt), &off, rec, &cc, NULL, 0xFFFFFFFF); /* compressed copy */
            pkt[7] = 2;
            rr_parse_sweep(pkt, first_end);
            rr_parse_sweep(pkt, off);
            total++;
        }
    }
    zone_arena_destroy(&z);
    printf("  -> %zu RR types round-tripped through the sweeps.\n", total);
}

/* Name encoding / decoding corner cases. */
static void test_wire_name_edges(void) {
    printf("[TEST] Sweep: wire name encode/decode corner cases...\n");
    uint8_t p[600]; char nb[300]; size_t nx; char *nm;
    zone_arena_t a; memset(&a, 0, sizeof(a)); zone_arena_init(&a);
    /* crafted packets: forward pointer, self loop, pointer chain, 0x40/0x80 label, long names */
    const uint8_t cases[][24] = {
        { 0xC0, 12 },                         /* pointer to itself */
        { 0xC0, 14, 0xC0, 12 },               /* forward pointer   */
        { 0x40, 1, 'a', 0 },                  /* extended label    */
        { 0x80, 1, 'a', 0 },                  /* reserved label    */
        { 1, 'a', 0xC0 },                     /* truncated pointer */
        { 3, 'a', 'b' },                      /* truncated label   */
        { 1, 'A', 1, 'b', 0 },                /* ok                */
        { 1, '.', 1, '\\', 1, ' ', 0 },        /* escaped characters */
        { 0 },                                /* root              */
    };
    for (size_t c = 0; c < NELEM(cases); c++) {
        memset(p, 0, sizeof(p));
        memcpy(p + 12, cases[c], sizeof(cases[c]));
        for (size_t len = 12; len <= 12 + 8; len++) {
            (void)skip_wire_name(p, len, 12, &nx);
            (void)expand_wire_name(p, len, 12, &nx, &a, &nm);
            (void)extract_wire_name_to_buffer(p, len, 12, &nx, nb, sizeof(nb));
            (void)extract_wire_name_to_buffer(p, len, 12, &nx, nb, 3);
        }
    }
    /* backward pointer chain: 12:"a"->0 ; 15: ptr->12 ; 17: 1 'b' ptr->15 */
    memset(p, 0, sizeof(p));
    uint8_t chain[] = { 1, 'a', 0, 0xC0, 12, 1, 'b', 0xC0, 15 };
    memcpy(p + 12, chain, sizeof(chain));
    assert(expand_wire_name(p, 12 + sizeof(chain), 17, &nx, &a, &nm) == 0);
    /* maximum-length name (255) and one that is too long */
    size_t off = 12;
    for (int l = 0; l < 4; l++) { p[off++] = 63; memset(p + off, 'x', 63); off += 63; }
    p[off++] = 0;
    (void)expand_wire_name(p, off, 12, &nx, &a, &nm);
    (void)extract_wire_name_to_buffer(p, off, 12, &nx, nb, sizeof(nb));
    (void)skip_wire_name(p, off, 12, &nx);
    /* write_uncompressed_name / write_dns_name_str / compress_name limits */
    char longname[400]; size_t lo = 0;
    for (int l = 0; l < 5; l++) { memset(longname + lo, 'y', 60); lo += 60; longname[lo++] = '.'; }
    longname[lo] = 0;
    const char *names[] = { "a.b.c.", "a\\.b.c.", "\\065\\066.c.", "a..b.", ".", "", longname,
                            "x\\", "\\256.example.", "\\0a.example.", "tab\\ x.example." };
    compress_ctx_t cc; compress_ctx_init(&cc);
    for (size_t i = 0; i < NELEM(names); i++) {
        for (size_t lim = 12; lim < 80; lim += 3) {
            (void)write_uncompressed_name(p, 12, lim, names[i]);
            uint16_t o2 = 12;
            (void)write_dns_name_str(p, &o2, names[i], &cc, lim);
            (void)write_dns_name_str(p, &o2, names[i], NULL, lim);
        }
    }
    /* many distinct names -> compression table churn and generation wrap */
    compress_ctx_init(&cc);
    cc.current_generation = 0xFFFF;
    compress_ctx_init_packet(&cc);
    uint8_t big[16384]; uint16_t bo = 12;
    memset(big, 0, 12);
    for (int i = 0; i < 600; i++) {
        char nm2[64]; snprintf(nm2, sizeof(nm2), "h%d.z%d.example.", i, i % 7);
        if (write_dns_name_str(big, &bo, nm2, &cc, sizeof(big)) != 0) break;
    }
    register_wire_name_for_compression(big, 12, &cc);
    register_wire_name_for_compression(big, 0x3FFF, &cc);
    zone_arena_destroy(&a);
    printf("  -> wire name corner cases passed.\n");
}

/* TSIG sign / verify with every algorithm, truncations and mutations. */
static void test_wire_tsig_sweep(void) {
    printf("[TEST] Sweep: TSIG sign/verify across algorithms, truncation and tampering...\n");
    const char *algs[] = { "hmac-md5.sig-alg.reg.int.", "hmac-sha1", "hmac-sha224", "hmac-sha256",
                           "hmac-sha384", "hmac-sha512", NULL, "hmac-bogus" };
    for (size_t ai = 0; ai < NELEM(algs); ai++) {
        tsig_key_t k; memset(&k, 0, sizeof(k));
        k.name = "tsig-key.example."; k.algorithm = (char *)algs[ai];
        memset(k.secret_decoded, 0x5A, 32); k.secret_decoded_len = 32;
        (void)tsig_algorithm_is_supported(algs[ai] ? algs[ai] : "x");
        uint8_t pkt[1024]; size_t len = sw_build(pkt, 0x4242, 0x00, 0, "www.example.", 1, 1, Q_EDNS);
        size_t base = len;
        for (size_t mx = base; mx < base + 120; mx += 9) {
            size_t l2 = base;
            (void)tsig_sign_packet(pkt, &l2, mx, &k, 0, NULL, NULL, NULL, 0, false);
        }
        uint8_t mac[64]; size_t maclen = sizeof(mac);
        len = base;
        int rc = tsig_sign_packet(pkt, &len, sizeof(pkt), &k, 0, mac, &maclen, NULL, 0, false);
        if (rc != 0) continue;
        uint8_t vmac[64]; size_t vlen = 0;
        (void)tsig_verify_packet(pkt, len, &k, NULL, 0, NULL, 0, false, vmac, &vlen);
        (void)packet_has_tsig(pkt, len);
        for (size_t cut = 0; cut < len; cut++) {
            (void)tsig_verify_packet(pkt, cut, &k, NULL, 0, NULL, 0, false, vmac, &vlen);
            (void)packet_has_tsig(pkt, cut);
        }
        uint8_t m[1024];
        for (size_t pos = 0; pos < len; pos++) {
            memcpy(m, pkt, len); m[pos] ^= 0x01;
            (void)tsig_verify_packet(m, len, &k, NULL, 0, NULL, 0, false, NULL, NULL);
        }
        tsig_key_t k2 = k; k2.algorithm = "hmac-sha512";
        (void)tsig_verify_packet(pkt, len, &k2, NULL, 0, NULL, 0, false, vmac, &vlen);
        k2 = k; k2.fuzztime = 1;           /* BADTIME */
        (void)tsig_verify_packet(pkt, len, &k2, NULL, 0, NULL, 0, false, vmac, &vlen);
        (void)tsig_verify_packet(pkt, len, NULL, NULL, 0, NULL, 0, false, vmac, &vlen);
        /* multi-message: response signed with the request MAC, then a subsequent message
         * with unsigned intermediates in between */
        uint8_t r1[1024]; size_t r1l = sw_build(r1, 0x4242, 0x84, 0, "www.example.", 1, 1, 0);
        uint8_t pm[64]; memcpy(pm, mac, maclen); size_t pml = maclen;
        (void)tsig_sign_packet(r1, &r1l, sizeof(r1), &k, 0, pm, &pml, NULL, 0, false);
        (void)tsig_verify_packet(r1, r1l, &k, mac, maclen, NULL, 0, false, vmac, &vlen);
        uint8_t inter[40]; memset(inter, 0x33, sizeof(inter));
        uint8_t r2[1024]; size_t r2l = sw_build(r2, 0x4242, 0x84, 0, "www.example.", 1, 1, 0);
        uint8_t pm2[64]; memcpy(pm2, pm, pml); size_t pml2 = pml;
        (void)tsig_sign_packet(r2, &r2l, sizeof(r2), &k, 0, pm2, &pml2, inter, sizeof(inter), true);
        (void)tsig_verify_packet(r2, r2l, &k, pm, pml, inter, sizeof(inter), true, vmac, &vlen);
        (void)tsig_verify_packet(r2, r2l, &k, pm, pml, NULL, 0, true, vmac, &vlen);
        /* error-code signing (BADSIG/BADTIME responses) */
        r1l = sw_build(r1, 0x4242, 0x84, 0, "www.example.", 1, 1, 0);
        (void)tsig_sign_packet(r1, &r1l, sizeof(r1), &k, 16, NULL, NULL, NULL, 0, false);
        r1l = sw_build(r1, 0x4242, 0x84, 0, "www.example.", 1, 1, 0);
        (void)tsig_sign_packet(r1, &r1l, sizeof(r1), &k, 18, NULL, NULL, NULL, 0, false);
        (void)tsig_verify_packet(r1, r1l, &k, NULL, 0, NULL, 0, false, vmac, &vlen);
    }
    (void)tsig_prewarm_crypto();
    uint8_t x[4] = {1,2,3,4}, y[4] = {1,2,3,5};
    assert(const_time_memcmp(x, x, 4) == 0 && const_time_memcmp(x, y, 4) != 0);
    printf("  -> TSIG sweeps passed.\n");
}

/* EDNS option assembly with small buffers and every option combination. */
static void test_wire_edns_sweep(void) {
    printf("[TEST] Sweep: EDNS parse/assemble combinations...\n");
    server_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.nsid_string = "nsid-value"; cfg.tcp_connection_reuse = true; cfg.tcp_idle_timeout = 70000;
    uint8_t req[512], res[2048];
    for (unsigned q = 0; q < (1u << 11); q += 7) {
        size_t len = sw_build(req, 1, 1, 0, "a.example.", 1, 1, q | Q_EDNS);
        edns_info_t e;
        uint16_t qd = 1, an = 0, ns = 0, ar = 1;
        if (parse_edns_opt(req, len, qd, an, ns, ar, &e) != 0) continue;
        if (q & 4) { e.ede_count = 2; e.ede_list[0].code = 3; strcpy(e.ede_list[0].text, "stale"); e.ede_list[1].code = 18; }
        for (size_t lim = 0; lim < 140; lim += 5) {
            for (int tcp = 0; tcp < 2; tcp++) {
                uint16_t off = 12, arc = 0;
                assemble_edns_opt(res, lim, &off, &arc, &e, (uint8_t)(q & 3), tcp, (q & 8) ? &cfg : NULL);
            }
        }
        for (size_t cut = 12; cut < len; cut++) (void)parse_edns_opt(req, cut, qd, an, ns, ar, &e);
        for (size_t pos = 12; pos < len; pos++) {
            uint8_t m[512]; memcpy(m, req, len); m[pos] ^= 0x80;
            (void)parse_edns_opt(m, len, qd, an, ns, ar, &e);
            m[pos] = 0xFF; (void)parse_edns_opt(m, len, qd, an, ns, ar, &e);
        }
    }
    for (size_t lim = 0; lim < 40; lim += 3) {
        uint16_t off = 12, arc = 0;
        assemble_edns_opt(res, lim, &off, &arc, NULL, 0, false, &cfg);
        assemble_edns_opt(res, lim, &off, &arc, NULL, 1, true, NULL);
    }
    {   /* ECS response with odd family/prefix values, KariDNS ext */
        edns_info_t e; memset(&e, 0, sizeof(e)); e.present = true; e.udp_payload_size = 1232;
        e.has_ecs = true; e.has_karidns_ext = true; e.karidns_ext_version = 1; e.karidns_ext_hash = 7;
        uint8_t fam[] = { 1, 2, 3 }; uint8_t pre[] = { 0, 7, 24, 33, 64, 129, 255 };
        cfg.ecs_enable = true;
        for (size_t f = 0; f < 3; f++) for (size_t pp = 0; pp < NELEM(pre); pp++) {
            e.ecs_family = fam[f]; e.ecs_source_prefix = pre[pp]; e.ecs_scope_prefix = pre[pp];
            uint16_t off = 12, arc = 0;
            assemble_edns_opt(res, sizeof(res), &off, &arc, &e, 0, false, &cfg);
            off = 12; arc = 0;
            assemble_edns_opt(res, sizeof(res), &off, &arc, &e, 0, false, NULL);
        }
        cfg.ecs_enable = false;
        uint16_t off = 12, arc = 0;
        assemble_edns_opt(res, sizeof(res), &off, &arc, &e, 0, false, &cfg);
        e.has_keepalive_query = true; cfg.tcp_idle_timeout = 0;
        off = 12; assemble_edns_opt(res, sizeof(res), &off, &arc, &e, 0, true, &cfg);
        cfg.tcp_idle_timeout = 50;
        off = 12; assemble_edns_opt(res, sizeof(res), &off, &arc, &e, 0, true, &cfg);
        e.ede_count = MAX_EDE_COUNT;
        for (int i = 0; i < MAX_EDE_COUNT; i++) { e.ede_list[i].code = (uint16_t)i; memset(e.ede_list[i].text, 'e', sizeof(e.ede_list[i].text) - 1); e.ede_list[i].text[sizeof(e.ede_list[i].text) - 1] = 0; }
        for (size_t lim = 12; lim < 2048; lim += 50) { off = 12; arc = 0; assemble_edns_opt(res, lim, &off, &arc, &e, 0, true, &cfg); }
    }
    {   /* EDNS option edge values: long cookies, many EDEs, KariDNS ext, bad ECS */
        uint8_t q[1200]; size_t ql = sw_build(q, 1, 1, 0, "a.example.", 1, 1, 0);
        q[11] = 1;
        size_t o = ql;
        q[o++] = 0; q[o++] = 0; q[o++] = 41; q[o++] = 4; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0;
        size_t rdp = o; o += 2;
        const uint8_t opts[][12] = {
            { 0, 10, 0, 8, 1,2,3,4,5,6,7,8 },
            { 0, 10, 0, 8, 1,2,3,4,5,6,7,8 },     /* duplicate cookie ignored */
            { 0, 15, 0, 2, 0, 9 },                /* EDE without text          */
            { 0, 15, 0, 1, 0 },                   /* EDE too short             */
            { 0, 11, 0, 0 }, { 0, 11, 0, 0 },     /* duplicate keepalive       */
            { 0, 21, 0, 0 },                      /* MQTYPE-Response in query  */
            { 0, 20, 0, 3, 0, 1, 0 },             /* odd MQTYPE length         */
            { 0, 20, 0, 2, 0, 1 },                /* duplicate MQTYPE          */
            { 0xFE, 0x81, 0, 5, 1, 0, 0, 0, 9 },  /* KariDNS ext               */
            { 0xFE, 0x81, 0, 1, 1 },              /* KariDNS ext bad length    */
            { 0, 8, 0, 4, 0, 1, 0, 0 },           /* ECS /0                    */
            { 0, 8, 0, 4, 0, 1, 0, 0 },           /* duplicate ECS             */
        };
        const uint8_t optlen[] = { 12, 12, 6, 5, 4, 4, 4, 7, 6, 9, 5, 8, 8 };
        for (size_t i = 0; i < NELEM(opts); i++) { memcpy(q + o, opts[i], optlen[i]); o += optlen[i]; }
        /* 30 EDE options to overflow MAX_EDE_COUNT */
        for (int i = 0; i < 70; i++) { q[o++] = 0; q[o++] = 15; q[o++] = 0; q[o++] = 3; q[o++] = 0; q[o++] = (uint8_t)i; q[o++] = 'x'; }
        uint16_t rl = (uint16_t)(o - rdp - 2); q[rdp] = (uint8_t)(rl >> 8); q[rdp + 1] = (uint8_t)rl;
        edns_info_t e2;
        (void)parse_edns_opt(q, o, 1, 0, 0, 1, &e2);
        const uint8_t badecs[][12] = {
            { 0, 8, 0, 3, 0, 1, 0 }, { 0, 8, 0, 4, 0, 3, 0, 0 }, { 0, 8, 0, 4, 0, 1, 33, 0 },
            { 0, 8, 0, 4, 0, 2, 129, 0 }, { 0, 8, 0, 5, 0, 1, 8, 1, 10 }, { 0, 8, 0, 4, 0, 1, 8, 0 },
            { 0, 8, 0, 5, 0, 1, 7, 0, 0xFF }, { 0, 10, 0, 50 }, { 0, 10, 0, 12, 1,2,3,4,5,6,7,8 },
        };
        const uint8_t badlen[] = { 7, 8, 8, 8, 9, 8, 9, 4, 12 };
        for (size_t i = 0; i < NELEM(badecs); i++) {
            o = rdp + 2; memcpy(q + o, badecs[i], badlen[i]); o += badlen[i];
            if (i == 8) { memset(q + o, 9, 4); o += 4; }
            rl = (uint16_t)(o - rdp - 2); q[rdp] = (uint8_t)(rl >> 8); q[rdp + 1] = (uint8_t)rl;
            (void)parse_edns_opt(q, o, 1, 0, 0, 1, &e2);
        }
        /* 40-byte server cookie */
        o = rdp + 2; q[o++] = 0; q[o++] = 10; q[o++] = 0; q[o++] = 40; memset(q + o, 7, 40); o += 40;
        rl = (uint16_t)(o - rdp - 2); q[rdp] = (uint8_t)(rl >> 8); q[rdp + 1] = (uint8_t)rl;
        (void)parse_edns_opt(q, o, 1, 0, 0, 1, &e2);
    }
    /* OPT in the wrong section, two OPT RRs, non-root owner */
    size_t len = sw_build(req, 1, 1, 0, "a.example.", 1, 1, Q_EDNS);
    edns_info_t e;
    (void)parse_edns_opt(req, len, 1, 1, 0, 0, &e);
    memcpy(req + len, req + len - 11, 11); req[11] = 2;
    (void)parse_edns_opt(req, len + 11, 1, 0, 0, 2, &e);
    /* protobuf helpers */
    uint8_t pb[16];
    for (size_t c = 0; c < 12; c++) {
        (void)pb_encode_varint(pb, c, 0xFFFFFFFFFFFFULL);
        (void)pb_encode_tag(pb, c, 5, 2);
        (void)pb_encode_bytes_field(pb, c, 3, (const uint8_t *)"abcdef", 6);
        (void)pb_encode_varint_field(pb, c, 2, 300);
        (void)pb_encode_fixed32_field(pb, c, 1, 7);
    }
    printf("  -> EDNS sweeps passed.\n");
}

/* ===========================================================================
 * Zone-file parser sweeps: directive error table, token-level mutation of every
 * RR line, and each input parsed with and without an error sink.
 * ======================================================================== */
typedef struct { const char *name; const char *text; unsigned long ino; } vfile_t;
static const vfile_t VFILES[] = {
    { "inc1.zone", "www2 IN A 192.0.2.2\n$TTL 60\nwww3 A 192.0.2.3\n", 11 },
    { "sub/inc2.zone", "$INCLUDE inc1.zone\nx IN TXT \"inc2\"\n", 12 },
    { "loop.zone", "a IN A 192.0.2.1\n$INCLUDE loop.zone\n", 13 },
    { "bad.zone", "bad IN A not-an-ip\n", 14 },
    { "d1.zone", "$INCLUDE d2.zone\n", 21 }, { "d2.zone", "$INCLUDE d3.zone\n", 22 },
    { "d3.zone", "$INCLUDE d4.zone\n", 23 }, { "d4.zone", "$INCLUDE d5.zone\n", 24 },
    { "d5.zone", "$INCLUDE d6.zone\n", 25 }, { "d6.zone", "$INCLUDE d7.zone\n", 26 },
    { "d7.zone", "$INCLUDE d8.zone\n", 27 }, { "d8.zone", "$INCLUDE d9.zone\n", 28 },
    { "d9.zone", "$INCLUDE d10.zone\n", 29 }, { "d10.zone", "$INCLUDE d11.zone\n", 30 },
    { "d11.zone", "$INCLUDE d12.zone\n", 31 }, { "d12.zone", "$INCLUDE d13.zone\n", 32 },
    { "d13.zone", "$INCLUDE d14.zone\n", 33 }, { "d14.zone", "$INCLUDE d15.zone\n", 34 },
    { "d15.zone", "$INCLUDE d16.zone\n", 35 }, { "d16.zone", "$INCLUDE d17.zone\n", 36 },
    { "d17.zone", "$INCLUDE d18.zone\n", 37 }, { "d18.zone", "z IN A 192.0.2.18\n", 38 },
    { "tagged.zone", "$LOCATION office\nt IN A 10.0.0.1\n$ECS-SUBNET eu\nu IN A 198.51.100.1\n", 40 },
    { "empty.zone", "", 41 },
};
static char *vfile_cb(parse_context_t *ctx, const char *path, dev_t *dev, ino_t *ino) {
    (void)ctx;
    const char *base = strrchr(path, '/');
    for (size_t i = 0; i < NELEM(VFILES); i++) {
        size_t nl = strlen(VFILES[i].name), pl = strlen(path);
        if (pl >= nl && strcmp(path + pl - nl, VFILES[i].name) == 0 &&
            (pl == nl || path[pl - nl - 1] == '/')) {
            if (dev) *dev = 1;
            if (ino) *ino = (ino_t)VFILES[i].ino;
            return strdup(VFILES[i].text);
        }
    }
    (void)base;
    return NULL;
}

static int zp_parse(const char *text, int mode) {
    zone_arena_t a; memset(&a, 0, sizeof(a)); zone_arena_init(&a);
    parse_error_t err = {0};
    char *vp[8] = {0}; dev_t vd[8] = {0}; ino_t vi[8] = {0};
    char *ttl = NULL, *ecs = NULL, *loc = NULL;
    const char *all[] = { "example.", "sub.example.", "other.test." };
    parse_context_t ctx = { .base_dir = "/zones", .default_origin = "example.",
                            .is_standalone_mode = (mode & 2) == 0,
                            .err_out = (mode & 1) ? NULL : &err,
                            .visited_paths = vp, .visited_devs = (mode & 4) ? NULL : vd,
                            .visited_inos = (mode & 4) ? NULL : vi, .visited_cap = (mode & 8) ? 1 : 8,
                            .load_file_cb = vfile_cb, .shared_ttl_io = &ttl,
                            .shared_ecs_tag_io = &ecs, .shared_loc_tag_io = &loc,
                            .all_zone_names = all, .all_zone_count = 3 };
    char *buf = arena_strdup(&a, text);
    int rc = parse_zone_fast(buf, strlen(buf), &a, (mode & 16) ? NULL : &ctx);
    if (rc >= 0) (void)build_zone_index(&a, (mode & 1) != 0);
    zone_arena_destroy(&a);
    return rc;
}

static const char *ZP_SNIPPETS[] = {
    "$TTL\n", "$TTL abc\n", "$TTL 1w2d3h4m5s\na A 192.0.2.1\n", "$TTL 4294967296\n", "$TTL 1x\n",
    "$ORIGIN\n", "$ORIGIN rel\na A 192.0.2.1\n", "$ORIGIN a\\.b.\nx A 192.0.2.1\n", "$ORIGIN x\\\\.\n",
    "$ORIGIN x\\\\\\.\na A 192.0.2.1\n", "$ORIGIN .\na A 192.0.2.1\n",
    "$INCLUDE\n", "$INCLUDE /abs/inc1.zone\n", "$INCLUDE ../inc1.zone\n", "$INCLUDE sub/..\n",
    "$INCLUDE ./././inc1.zone\n", "$INCLUDE inc1.zone sub.example.\n", "$INCLUDE missing.zone\n",
    "$INCLUDE loop.zone\n", "$INCLUDE d1.zone\n", "$INCLUDE bad.zone\n", "$INCLUDE sub/inc2.zone\n",
    "$INCLUDE tagged.zone\n", "$INCLUDE empty.zone\n", "$INCLUDE \"\"\n",
    "$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n$INCLUDE inc1.zone\n",
    "$GENERATE 1-3 host$ A 10.0.0.$\n", "$GENERATE 1-4/2 host$ 300 IN A 10.0.0.$\n",
    "$GENERATE 1-3/0 h$ A 10.0.0.$\n", "$GENERATE 3-1 h$ A 10.0.0.$\n", "$GENERATE x-3 h$ A 10.0.0.$\n",
    "$GENERATE 1-x h$ A 10.0.0.$\n", "$GENERATE 1 h$ A 10.0.0.$\n", "$GENERATE 1-3/x h$ A 10.0.0.$\n",
    "$GENERATE 1-3x h$ A 10.0.0.$\n", "$GENERATE 1-99999999999 h$ A 10.0.0.1\n",
    "$GENERATE 1-10000000 h$ A 10.0.0.1\n", "$GENERATE 1-3 h${0,3,d} A 10.0.0.${1,1,x}\n",
    "$GENERATE 1-3 h${1,65,x} A 10.0.0.$\n", "$GENERATE 1-3 h${1,3,q} A 10.0.0.$\n",
    "$GENERATE 1-3 h${1,3 A 10.0.0.$\n", "$GENERATE 1-3 h${ A 10.0.0.$\n", "$GENERATE 1-3 h${-1} A 10.0.0.$\n",
    "$GENERATE 1-3 h$$ A 10.0.0.$\n", "$GENERATE 1-3 h\\$ A 10.0.0.$\n", "$GENERATE 10-12 h${0,4,X} A 10.0.0.$\n",
    "$GENERATE 8-9 h${0,3,o} AAAA 2001:db8::$\n", "$GENERATE 1-2 c$ CNAME t$.example.\n",
    "$GENERATE 1-2 $ PTR h$.example.\n", "$GENERATE 1-2 d$ DNAME t$.example.\n", "$GENERATE 1-2 n$ NS ns$\n",
    "$GENERATE 1-2 h$ IN 300 A 10.0.0.$\n", "$GENERATE 1-2 h$ CH A 10.0.0.$\n", "$GENERATE 1-2 h$ TXT x\n",
    "$GENERATE 1-2 h$ A\n", "$GENERATE 1-2\n", "$GENERATE\n",
    "$GENERATE 1-2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$ A 10.0.0.$\n",
    "$GENERATE 1-2 c$ CNAME aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$.example.\n",
    "$GENERATE 1-2 h$ A 10.0.0.${0,0,d}\n",
    "a IN A (\n192.0.2.1 )\n", "a IN A ( 192.0.2.1\n", "a IN A 192.0.2.1 )\n", "a IN TXT ( \"x\" ( \"y\" ) )\n",
    "a IN TXT \"unterminated\n", "a IN TXT \"a\\\"b\" ; comment\n", "a IN TXT ( ; c\n \"x\" )\n",
    "a IN TXT \"\\065\\066\\\\\"\n", "a IN TXT \"\\999\"\n", "a IN TXT abc\\\n",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa IN A 192.0.2.1\n",
    "a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaa IN A 192.0.2.1\n",
    "a IN CNAME aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.\n",
    "$LOCATION-TAG office 10.0.0.0/8 2001:db8::/32\n$LOCATION office\nx A 192.0.2.1\n$LOCATION none\n",
    "$LOCATION-TAG office { 10.0.0.0/8; 192.168.0.0/16; };\n$LOCATION office\nx A 192.0.2.1\n",
    "$LOCATION-TAG\n", "$LOCATION-TAG t bogus/99\n", "$LOCATION-TAG t {\n", "$LOCATION\n",
    "$LOCATION unknown\nx A 192.0.2.1\n", "$LOCATION \"\"\n", "$LOCATION default\n",
    "$ECS-SUBNET-TAG eu 198.51.100.0/24\n$ECS-SUBNET eu\ny A 192.0.2.2\n$ECS-SUBNET \"\"\n",
    "$ECS-SUBNET-TAG\n", "$ECS-SUBNET\n", "$ECS-SUBNET nope\n", "$ECS-SUBNET-TAG e { 1.2.3.0/24 }\n",
    "$FOO bar\n", "$\n", "   A 192.0.2.9\n", "@ A 192.0.2.9\n\t300 IN AAAA 2001:db8::9\n",
    "a 300 IN A 192.0.2.1\na IN 300 A 192.0.2.1\na CH TXT \"x\"\na HS A 192.0.2.1\na NONE A 192.0.2.1\n",
    "a 1h30m A 192.0.2.1\na 99999999999 A 192.0.2.1\na 2w A 192.0.2.1\n",
    "a IN TYPE1 \\# 4 C0000201\na IN TYPE1 \\# 3 C00002\na IN TYPE1 \\# x\na IN TYPE1 \\# 2 ZZ\n",
    "a IN A 192.0.2.1\na IN CNAME b\n", "a IN BOGUS x\n", "a IN\n", "a\n", "a 300\n",
    "\n\n;only comment\n", "a IN A 192.0.2.1 ; trailing\r\nb IN A 192.0.2.2\r\n",
    "a\\ b IN A 192.0.2.1\n", "\\@ IN A 192.0.2.1\n", "a.. IN A 192.0.2.1\n", ".a IN A 192.0.2.1\n",
    "a IN SOA ns h ( 1 2 3 4 5 )\n", "a IN SOA ns h 1 2 3 4\n", "a IN SOA ns h 1w 2d 3h 4m 5s\n",
    "a IN NS \n", "* IN A 192.0.2.1\n*.x IN MX 10 y\n", "a IN MX x y\n", "a IN SRV 1 2 x t\n",
};

static void test_zone_parser_sweep(void) {
    printf("[TEST] Sweep: zone-file parser directives and token mutations...\n");
    const char *head = "$ORIGIN example.\n$TTL 300\n@ IN SOA ns.example. h.example. 1 7200 3600 1209600 300\n@ IN NS ns.example.\n";
    char buf[8192];
    for (size_t i = 0; i < NELEM(ZP_SNIPPETS); i++) {
        snprintf(buf, sizeof(buf), "%s%s", head, ZP_SNIPPETS[i]);
        for (int mode = 0; mode < 32; mode++) (void)zp_parse(buf, mode);
        (void)zp_parse(ZP_SNIPPETS[i], 0);
    }
    /* token-level mutation of every RR line */
    static const char *tok_garbage[] = { "", "x", "-1", "99999999999", "65536", "0", "(", ")", "\"", "\\",
        "a..b", "*", "@", "IN", "TYPE0", "\\# 1 zz", "1:1.2.3.0/33", "1.2.3.4.5", "::g", "=" };
    for (size_t i = 0; i < NELEM(RR_LINES); i++) {
        char line[1024];
        strncpy(line, RR_LINES[i], sizeof(line) - 1); line[sizeof(line) - 1] = 0;
        char *toks[40]; int nt = 0;
        for (char *t = strtok(line, " "); t && nt < 40; t = strtok(NULL, " ")) toks[nt++] = t;
        for (int ti = 1; ti < nt; ti++) {
            for (size_t g = 0; g < NELEM(tok_garbage); g++) {
                size_t o = (size_t)snprintf(buf, sizeof(buf), "%sm 300", head);
                for (int k = 0; k < nt; k++) o += (size_t)snprintf(buf + o, sizeof(buf) - o, " %s", k == ti ? tok_garbage[g] : toks[k]);
                snprintf(buf + o, sizeof(buf) - o, "\n");
                (void)zp_parse(buf, (int)(g & 1));
            }
            /* drop trailing tokens */
            size_t o = (size_t)snprintf(buf, sizeof(buf), "%sm 300", head);
            for (int k = 0; k < ti; k++) o += (size_t)snprintf(buf + o, sizeof(buf) - o, " %s", toks[k]);
            snprintf(buf + o, sizeof(buf) - o, "\n");
            (void)zp_parse(buf, 0);
        }
    }
    printf("  -> zone parser sweeps passed.\n");
}

/* tinydns-data parser: every record type with malformed fields. */
static void test_tinydns_sweep(void) {
    printf("[TEST] Sweep: tinydns-data parser...\n");
    static const char *lines[] = {
        ".example.:192.0.2.1:a:300::", ".example.::ns.other.test.:300", "&sub.example.:192.0.2.2:ns:300::",
        "&sub.example.::ns.other.test.", "+www.example.:192.0.2.3:300:4000000070000000:",
        "=h.example.:192.0.2.4:300::", "@example.:192.0.2.5:mx:10:300::", "@example.::mail.other.test.:20",
        "'example.:v=spf1\\072-all\\040\\101:300::", ("'long.example.:" "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789:300"),
        "^4.2.0.192.in-addr.arpa.:h.example.:300", "Cc.example.:www.example.:300::",
        "Zexample.:ns.example.:h.example.:1:2:3:4:5:300::", "Zexample.:ns.example.::::::::",
        ":gen.example.:16:\\003abc:300::", ":gen.example.:99999:\\001:300", ":gen.example.:x:\\001",
        "3v6.example.:20010db8000000000000000000000001:300::", "6v6p.example.:20010db8000000000000000000000002:300::",
        "3v6.example.:zz", "Ssrv.example.:192.0.2.7:t:5060:1:2:300::", "Ssrv.example.::other.test.:53",
        "Nnaptr.example.:100:10:u:E2U+sip:!^.*$!sip\\072x@y!:.:300::", "Nnaptr.example.:1:2",
        "_ssh.example.:1:1:0123456789abcdef0123456789abcdef01234567:300::", "_ssh.example.:x",
        "%in:192.0.2", "%ex", "+loc.example.:192.0.2.9:300::in", "+ttd.example.:192.0.2.10:0:4000000060000000:",
        "+badts.example.:192.0.2.11:300:zzzz:", "+upper.example.:192.0.2.12:300:40000000ABCDEF00:",
        "+x.other.test.:192.0.2.13", "+:192.0.2.14", "+a.example.:not-ip", "#comment", "-disabled.example.:1.2.3.4",
        "?unknown", "", ".example.:192.0.2.1:\\141\\142:300",
    };
    for (size_t i = 0; i < NELEM(lines); i++) {
        for (int mode = 0; mode < 4; mode++) {
            zone_arena_t a; memset(&a, 0, sizeof(a)); zone_arena_init(&a);
            parse_error_t err = {0};
            const char *all[] = { "example.", "sub.example.", "2.0.192.in-addr.arpa." };
            parse_context_t ctx = { .base_dir = ".", .default_origin = "example.", .is_standalone_mode = true,
                                    .err_out = (mode & 1) ? NULL : &err,
                                    .all_zone_names = (mode & 2) ? all : NULL, .all_zone_count = (mode & 2) ? 3 : 0 };
            char tb[1024]; snprintf(tb, sizeof(tb), "%s\n%s\n", lines[i], lines[(i + 1) % NELEM(lines)]);
            char *b = arena_strdup(&a, tb);
            (void)parse_tinydns_data(b, strlen(b), &a, &ctx);
            zone_arena_destroy(&a);
        }
    }
    printf("  -> tinydns sweeps passed.\n");
}

/* ===========================================================================
 * Snapshot rebuild / catalog membership state machine: a sequence of catalog
 * zone versions (groups changed, members added/removed, change-of-ownership,
 * broken catalogs) replayed across two views, with full rebuilds in between.
 * ======================================================================== */
static char g_sdir[256];
static void sfile(const char *name, const char *text) {
    char p[512]; snprintf(p, sizeof(p), "%s/%s", g_sdir, name);
    FILE *f = fopen(p, "w"); assert(f); fputs(text, f); fclose(f);
}

#define CAT_HEAD(z) "$ORIGIN " z "\n$TTL 300\n@ IN SOA ns." z " h." z " %d 7200 3600 1209600 300\n@ IN NS ns." z "\nns IN A 192.0.2.1\n"
static const char *CAT1_V[] = {
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\n"
    "uid1.zones IN PTR m1.example.\ngroup.uid1.zones IN TXT \"b\"\ngroup.uid1.zones IN TXT \"a\"\n"
    "uid2.zones IN PTR m2.example.\nuid5.zones IN PTR static.example.\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\n"
    "uid1.zones IN PTR m1.example.\ngroup.uid1.zones IN TXT \"c\"\n"
    "uid3.zones IN PTR m3.example.\ngroup.uid3.zones IN TXT \"x\"\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\n"
    "uid1.zones IN PTR m1.example.\ngroup.uid1.zones IN TXT \"c\"\ncoo.uid1.zones IN PTR cat2.example.\n"
    "uid3.zones IN PTR m3.example.\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\nuid3.zones IN PTR m3.example.\n"
    "uid4.zones IN PTR m4.example.\nuid4b.zones IN PTR m4.example.\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"1\"\nuid3.zones IN PTR m3.example.\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\nuid3.zones IN PTR m3.example.\n"
    "coo.uid3.zones IN PTR cat2.example.\ncoo.uid3.zones IN PTR cat9.example.\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\n",
    CAT_HEAD("cat1.example.") "version IN TXT \"2\"\n"
    "uid1.zones IN PTR m1.example.\ngroup.uid1.zones IN TXT \"a\"\ngroup.uid1.zones IN TXT \"b\"\n"
    "uid2.zones IN PTR m2.example.\ngroup.uid2.zones IN TXT \"z\"\nuid6.zones IN PTR bad..name.\n",
};
static const char *CAT2_V[] = {
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuidA.zones IN PTR n1.example.\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuidA.zones IN PTR n1.example.\nuidB.zones IN PTR m2.example.\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuidA.zones IN PTR n1.example.\nuid9.zones IN PTR m1.example.\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuid9.zones IN PTR m1.example.\ngroup.uid9.zones IN TXT \"moved\"\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuid3.zones IN PTR m3.example.\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuidA.zones IN PTR n1.example.\n",
    CAT_HEAD("cat2.example.") "version IN TXT \"2\"\nuidA.zones IN PTR n1.example.\n",
};

static void snap_process_catalogs(server_config_t *cfg) {
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    if (!snap) return;
    retain_zone_snapshot(snap);
    const char *cats[] = { "cat1.example.", "cat2.example." };
    size_t vc = snap->view_count;
    char vnames[4][64]; zone_db_entry_t *ents[4][2];
    for (size_t v = 0; v < vc && v < 4; v++) {
        snprintf(vnames[v], sizeof(vnames[v]), "%s", snap->views[v].name ? snap->views[v].name : "");
        for (int c = 0; c < 2; c++) ents[v][c] = find_zone_in_view(&snap->views[v], cats[c]);
    }
    release_zone_snapshot(snap);
    for (size_t v = 0; v < vc && v < 4; v++) {
        for (int c = 0; c < 2; c++) {
            zone_config_t *zc = find_zone_config_in_view(cfg, vnames[v], cats[c]);
            if (!ents[v][c] || !zc) continue;
            (void)reload_master_zone(ents[v][c], zc);
            catalog_process_membership(ents[v][c], zc, vnames[v]);
        }
    }
}

static void test_snapshot_catalog_sequence(void) {
    printf("[TEST] Sweep: snapshot rebuild + catalog membership state machine...\n");
    snprintf(g_sdir, sizeof(g_sdir), "/tmp/karidns_sweep_XXXXXX");
    assert(mkdtemp(g_sdir));
    sfile("static.zone", "$ORIGIN static.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.7\n");
    sfile("broken.zone", "$ORIGIN broken.example.\n@ IN SOA ns h 1 2 3 4 5\nx IN A nope\n");
    sfile("nosoa.zone", "$ORIGIN nosoa2.example.\n$TTL 60\n@ IN NS ns\nns IN A 192.0.2.8\n");
    sfile("notify.zone", "$ORIGIN notify.example.\n$TTL 60\n@ IN SOA ns1.notify.example. h 1 2 3 4 5\n"
          "@ IN NS ns1.notify.example.\n@ IN NS ns2.notify.example.\n@ IN NS ns3.notify.example.\n@ IN NS ns.static.example.\n@ IN NS ns.nowhere.test.\n@ IN NS\n"
          "ns1 IN A 192.0.2.101\nns2 IN A 192.0.2.102\nns2 IN AAAA 2001:db8::102\nns3 IN A 192.0.2.103\nns3 IN AAAA 2001:db8::103\n");
    static char conf[16384];
    snprintf(conf, sizeof(conf),
        "options { directory \"%s\"; additional-from-auth yes; };\n"
        "view \"internal\" { match-clients { 10.0.0.0/8; };\n"
        "  zone \"cat1.example\" { type master; file \"%s/cat1.zone\"; catalog-zone yes; masters { 127.0.0.1; }; };\n"
        "  zone \"cat2.example\" { type master; file \"%s/cat2.zone\"; catalog-zone yes; masters { 127.0.0.1 port 5300; }; };\n"
        "  zone \"static.example\" { type master; file \"%s/static.zone\"; additional-from-auth in-domain; };\n"
        "  zone \"broken.example\" { type master; file \"%s/broken.zone\"; };\n"
        "  zone \"nosoa2.example\" { type master; file \"%s/nosoa.zone\"; };\n"
        "  zone \"missing.example\" { type master; file \"%s/missing.zone\"; };\n"
        "  zone \"sec.example\" { type slave; file \"%s/sec.zone\"; masters { 127.0.0.1; }; };\n"
        "  zone \"notify.example\" { type master; file \"%s/notify.zone\"; notify-source \"192.0.2.250\";\n"
        "      also-notify { 198.51.100.1; 198.51.100.1; 198.51.100.2 port 5353; 2001:db8::77; not-an-ip; 192.0.2.102; }; };\n"
        "};\n"
        "view \"external\" { match-clients { any; };\n"
        "  zone \"cat1.example\" { type master; file \"%s/cat1.zone\"; catalog-zone yes; };\n"
        "  zone \"static.example\" { type master; file \"%s/static.zone\"; };\n"
        "  zone \".\" { type master; file \"%s/static.zone\"; };\n"
        "  zone \"notify.example\" { type master; file \"%s/notify.zone\"; notify-source \"2001:db8::250\"; also-notify { 2001:db8::78; 198.51.100.3; }; };\n"
        "};\n", g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir, g_sdir);
    server_config_t *cfg = sw_conf(conf);
    atomic_store_explicit(&g_config_db.active, cfg, memory_order_release);
    for (size_t step = 0; step < NELEM(CAT1_V) * 2; step++) {
        size_t k = step % NELEM(CAT1_V);
        char b1[2048], b2[2048];
        snprintf(b1, sizeof(b1), CAT1_V[k], (int)step + 1);
        snprintf(b2, sizeof(b2), CAT2_V[k], (int)step + 1);
        sfile("cat1.zone", b1);
        sfile("cat2.zone", b2);
        if (step == 0 || (step % 3) == 0) rebuild_zone_db_from_config(cfg, (step & 1) != 0);
        snap_process_catalogs(cfg);
        snap_process_catalogs(cfg);          /* idempotent second pass: "unchanged" branches */
        zone_db_snapshot_t *snap = acquire_zone_snapshot();
        retain_zone_snapshot(snap);
        const char *probe[] = { "m1.example.", "m2.example.", "m3.example.", "m4.example.", "n1.example.",
                                "static.example.", "www.static.example.", "nothing.test.", "cat1.example." };
        for (size_t p = 0; p < NELEM(probe); p++) {
            zone_lookup_result_t r;
            (void)lookup_zone_across_views(snap, cfg, probe[p], NULL, &r);
            (void)lookup_zone_across_views(snap, cfg, probe[p], "internal", &r);
            (void)lookup_zone_across_views(snap, cfg, probe[p], "nope", &r);
            (void)snapshot_get_zone(snap, probe[p]);
            for (size_t v = 0; v < snap->view_count; v++) (void)find_zone_in_view(&snap->views[v], probe[p]);
        }
        release_zone_snapshot(snap);
    }
    rebuild_zone_db_from_config(cfg, true);
    {   /* NOTIFY fan-out: also-notify (v4/v6/dup/invalid), NS glue in-zone, in sibling zone, missing */
        int sp[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0);
        fcntl(sp[1], F_SETFL, O_NONBLOCK);
        int saved0 = g_notify_ipc[0], saved1 = g_notify_ipc[1];
        g_notify_ipc[0] = sp[0]; g_notify_ipc[1] = sp[1];
        send_notify_to_all("notify.example.", "internal");
        send_notify_to_all("notify.example.", "external");
        send_notify_to_all("notify.example.", NULL);
        send_notify_to_all("static.example.", "internal");
        send_notify_to_all("unknown.example.", "nope");
        for (int i = 0; i < 300; i++) send_notify_to_all("notify.example.", "internal");  /* fill -> EAGAIN */
        close(sp[0]);
        send_notify_to_all("notify.example.", "internal");                             /* peer gone */
        close(sp[1]);
        g_notify_ipc[0] = saved0; g_notify_ipc[1] = saved1;
    }
    (void)lookup_zone_across_views(NULL, cfg, "a.", NULL, NULL);
    (void)snapshot_get_zone(NULL, "a.");
    (void)find_zone_config_in_view(NULL, "internal", "a.");
    (void)find_zone_config_in_view(cfg, "internal", NULL);
    (void)find_zone_config_in_view(cfg, "nope", "static.example.");
    (void)find_zone_in_view(NULL, "a.");
    printf("  -> snapshot/catalog sequence passed.\n");
}

/* ===========================================================================
 * ECS / location / cookie helpers, RRL and dnstap edge cases.
 * ======================================================================== */
static ecs_tag_def_t *mk_tags(int parsed, int *count) {
    static const char *cidrs[] = { "198.51.100.0/24", "2001:db8::/32", "10.0.0.0/8", "bogus", "0.0.0.0/0", "::/0", "192.0.2.1" };
    ecs_tag_def_t *t = calloc(2, sizeof(*t));
    for (int d = 0; d < 2; d++) {
        t[d].tag = strdup(d ? "t-two" : "t-one");
        t[d].cidr_count = (int)NELEM(cidrs);
        t[d].cidrs = calloc(NELEM(cidrs), sizeof(ecs_cidr_entry_t));
        for (size_t i = 0; i < NELEM(cidrs); i++) {
            t[d].cidrs[i].cidr = strdup(cidrs[(i + (size_t)d * 2) % NELEM(cidrs)]);
            if (parsed) (void)cidr_entry_parse(&t[d].cidrs[i].parsed, t[d].cidrs[i].cidr);
        }
    }
    *count = 2;
    return t;
}

static void test_ecs_cookie_rrl_dnstap_edges(void) {
    printf("[TEST] Sweep: ECS/location/cookie, RRL and dnstap helpers...\n");
    /* ---- pack/unpack of tag definitions ---- */
    int tc = 0; ecs_tag_def_t *tags = mk_tags(0, &tc);
    uint8_t pk[512];
    size_t pl = pack_tag_def_rdata(pk, sizeof(pk), &tags[0]);
    assert(pl > 0);
    for (size_t cap = 0; cap < pl; cap++) (void)pack_tag_def_rdata(pk, cap, &tags[0]);
    assert(pack_tag_def_rdata(NULL, 10, &tags[0]) == 0 && pack_tag_def_rdata(pk, 10, NULL) == 0);
    pl = pack_tag_def_rdata(pk, sizeof(pk), &tags[0]);
    for (size_t cut = 0; cut <= pl; cut++) {
        ecs_tag_def_t *out = NULL; int cnt = 0;
        (void)unpack_tag_def_rdata(pk, cut, &out, &cnt);
        free_ecs_tags_array(out, cnt);
    }
    { ecs_tag_def_t *out = NULL; int cnt = 0;
      assert(!unpack_tag_def_rdata(NULL, 5, &out, &cnt) && !unpack_tag_def_rdata(pk, pl, NULL, &cnt) && !unpack_tag_def_rdata(pk, pl, &out, NULL)); }
    for (size_t cut = 0; cut < 40; cut++) {
        uint8_t rb[64]; for (size_t i = 0; i < sizeof(rb); i++) rb[i] = (uint8_t)(i % 5 == 0 ? 3 : 'a' + i % 26);
        rb[0] = (uint8_t)(cut % 4);
        char **res = NULL; int rc2 = 0;
        (void)unpack_trusted_resolvers_rdata(rb, cut, &res, &rc2);
        for (int i = 0; i < rc2; i++) free(res[i]);
        free(res);
        tinydns_location_entry_t *locs = NULL; int lc = 0;
        rb[2] = (uint8_t)(cut % 6);
        (void)unpack_tinydns_loc_rdata(rb, cut, &locs, &lc);
        free(locs);
    }
    { char **r = NULL; int c = 0; assert(!unpack_trusted_resolvers_rdata(NULL, 1, &r, &c)); uint8_t z0 = 0; assert(unpack_trusted_resolvers_rdata(&z0, 1, &r, &c)); }
    { tinydns_location_entry_t *l = NULL; int c = 0; assert(!unpack_tinydns_loc_rdata(NULL, 3, &l, &c)); }

    /* ---- tag resolution through zone / cfg / zcfg with parsed and string CIDRs ---- */
    zone_arena_t za; memset(&za, 0, sizeof(za)); zone_arena_init(&za);
    server_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    zone_config_t zc; memset(&zc, 0, sizeof(zc));
    const uint8_t a4[4] = { 198, 51, 100, 7 }, a4b[4] = { 203, 0, 113, 1 };
    const uint8_t a6[16] = { 0x20, 0x01, 0x0d, 0xb8, 1 };
    const char *ips[] = { "198.51.100.7", "10.1.1.1", "2001:db8::5", "203.0.113.9", "not-an-ip", NULL };
    for (int parsed = 0; parsed < 2; parsed++) {
        int n1, n2, n3;
        ecs_tag_def_t *zt = mk_tags(parsed, &n1), *ct = mk_tags(parsed, &n2), *ft = mk_tags(parsed, &n3);
        for (int where = 0; where < 4; where++) {
            za.bind_ecs_tags = where == 0 ? zt : NULL; za.bind_ecs_tag_count = where == 0 ? n1 : 0;
            za.bind_location_tags = where == 0 ? zt : NULL; za.bind_location_tag_count = where == 0 ? n1 : 0;
            cfg.ecs_tags = where == 1 ? ct : NULL; cfg.ecs_tag_count = where == 1 ? n2 : 0;
            cfg.location_tags = where == 1 ? ct : NULL; cfg.location_tag_count = where == 1 ? n2 : 0;
            zc.ecs_tags = where == 2 ? ft : NULL; zc.ecs_tag_count = where == 2 ? n3 : 0;
            zc.location_tags = where == 2 ? ft : NULL; zc.location_tag_count = where == 2 ? n3 : 0;
            for (int f = 0; f < 4; f++) {
                uint8_t sc = 0;
                const uint8_t *ad = f == 1 ? a6 : (f == 2 ? a4b : a4);
                uint16_t fam = f == 1 ? 2 : (f == 3 ? 7 : 1);
                (void)resolve_ecs_subnet_tag(&za, &cfg, &zc, ad, fam, &sc);
                (void)resolve_ecs_subnet_tag(&za, &cfg, &zc, ad, fam, NULL);
                (void)resolve_ecs_subnet_tag(NULL, &cfg, NULL, ad, fam, &sc);
                (void)resolve_ecs_subnet_tag(&za, NULL, &zc, NULL, fam, &sc);
            }
            for (size_t i = 0; i < NELEM(ips); i++) {
                (void)resolve_bind_location_tag(&za, &cfg, &zc, ips[i]);
                (void)resolve_bind_location_tag(NULL, NULL, &zc, ips[i]);
            }
        }
        free_ecs_tags_array(zt, n1); free_ecs_tags_array(ct, n2); free_ecs_tags_array(ft, n3);
    }
    za.bind_ecs_tags = NULL; za.bind_location_tags = NULL;
    /* trusted resolvers: zone parsed / zone strings / zcfg / cfg */
    char *tr[] = { "127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "any" };
    acl_entry_t *trp = acl_list_parse(tr, 3);
    for (int mode = 0; mode < 6; mode++) {
        memset(&cfg, 0, sizeof(cfg)); memset(&zc, 0, sizeof(zc));
        za.bind_ecs_trusted_resolvers = NULL; za.bind_ecs_trusted_resolver_count = 0; za.bind_ecs_trusted_resolvers_parsed = NULL;
        if (mode == 0) { za.bind_ecs_trusted_resolvers = tr; za.bind_ecs_trusted_resolver_count = 3; za.bind_ecs_trusted_resolvers_parsed = trp; }
        if (mode == 1) { za.bind_ecs_trusted_resolvers = tr; za.bind_ecs_trusted_resolver_count = 3; }
        if (mode == 2) { zc.ecs_trusted_resolvers = tr; zc.ecs_trusted_resolvers_count = 3; zc.ecs_trusted_resolvers_parsed = trp; }
        if (mode == 3) { zc.ecs_trusted_resolvers = tr; zc.ecs_trusted_resolvers_count = 4; }
        if (mode == 4) { cfg.ecs_trusted_resolvers = tr; cfg.ecs_trusted_resolvers_count = 3; cfg.ecs_trusted_resolvers_parsed = trp; }
        if (mode == 5) { cfg.ecs_trusted_resolvers = tr; cfg.ecs_trusted_resolvers_count = 3; }
        for (size_t i = 0; i < NELEM(ips); i++) {
            (void)is_ecs_trusted_resolver(&za, &cfg, &zc, ips[i]);
            (void)is_ecs_trusted_resolver(NULL, &cfg, NULL, ips[i]);
        }
    }
    free(trp);
    za.bind_ecs_trusted_resolvers = NULL; za.bind_ecs_trusted_resolver_count = 0; za.bind_ecs_trusted_resolvers_parsed = NULL;
    /* tinydns client location */
    tinydns_location_entry_t locs[3] = { { {'j','p'}, {192,0,2,0}, 3 }, { {'u','s'}, {10,0,0,0}, 1 }, { {'a','l'}, {0}, 0 } };
    za.locations = locs; za.location_count = 3;
    for (size_t i = 0; i < NELEM(ips); i++) { char lo[2]; tinydns_resolve_client_location(&za, ips[i], lo); }
    char lo2[2]; tinydns_resolve_client_location(&za, "192.0.2.77", lo2); tinydns_resolve_client_location(NULL, "1.2.3.4", lo2);
    za.locations = NULL; za.location_count = 0;
    zone_arena_destroy(&za);
    /* wrap_tinydns_record */
    {
        zone_arena_t w; memset(&w, 0, sizeof(w)); zone_arena_init(&w);
        dns_record_t r; memset(&r, 0, sizeof(r));
        r.name = "x.example."; r.type_code = 1; r.type = "A"; r.rdata[0] = "192.0.2.1"; r.rdata_count = 1; r.ttl_value = 60;
        r.tinydns_ttd = time(NULL) + 1000; r.tinydns_loc[0] = 'j'; r.tinydns_loc[1] = 'p';
        dns_record_t out; uint8_t wb[512];
        for (size_t cap = 0; cap < 64; cap += 3) (void)wrap_tinydns_record(&r, &out, wb, cap);
        (void)wrap_tinydns_record(&r, &out, wb, sizeof(wb));
        r.type_code = 16; r.type = "TXT"; r.rdata[0] = "\"\""; (void)wrap_tinydns_record(&r, &out, wb, sizeof(wb));
        r.type_code = 1; r.rdata[0] = "bad"; (void)wrap_tinydns_record(&r, &out, wb, sizeof(wb));
        assert(!wrap_tinydns_record(NULL, &out, wb, sizeof(wb)) && !wrap_tinydns_record(&r, NULL, wb, 9) && !wrap_tinydns_record(&r, &out, NULL, 9));
        zone_arena_destroy(&w);
    }
    /* ---- server cookies (RFC 9018) ---- */
    {
        server_config_t c; memset(&c, 0, sizeof(c));
        c.cookie_secret_count = 2; memset(c.cookie_secrets[0], 1, 16); memset(c.cookie_secrets[1], 2, 16);
        uint8_t cc8[8] = {1,2,3,4,5,6,7,8}, sc[SERVER_COOKIE_LEN];
        uint32_t now = (uint32_t)time(NULL);
        const char *cips[] = { "192.0.2.1", "2001:db8::1", "bogus", NULL };
        for (size_t i = 0; i < NELEM(cips); i++) {
            for (int age = 0; age < 5; age++) {
                uint32_t ts = now - (age == 1 ? 2000u : age == 2 ? 4000u : 0u) + (age == 3 ? 1000u : 0u);
                if (!generate_server_cookie(&c, cips[i], cc8, sc, ts)) continue;
                (void)verify_server_cookie(&c, cips[i], cc8, sc, SERVER_COOKIE_LEN, now);
                (void)verify_server_cookie(&c, cips[i], cc8, sc, 8, now);
                uint8_t bad[SERVER_COOKIE_LEN]; memcpy(bad, sc, sizeof(bad)); bad[0] ^= 0xFF;
                (void)verify_server_cookie(&c, cips[i], cc8, bad, SERVER_COOKIE_LEN, now);
                memcpy(bad, sc, sizeof(bad)); bad[1] = 0x7F;
                (void)verify_server_cookie(&c, cips[i], cc8, bad, SERVER_COOKIE_LEN, now);
                memcpy(bad, sc, sizeof(bad)); bad[15] ^= 1;
                (void)verify_server_cookie(&c, cips[i], cc8, bad, SERVER_COOKIE_LEN, now);
                /* cookie issued with the old (second) secret after rotation */
                server_config_t c2 = c; memcpy(c2.cookie_secrets[0], c.cookie_secrets[1], 16); memcpy(c2.cookie_secrets[1], c.cookie_secrets[0], 16);
                (void)verify_server_cookie(&c2, cips[i], cc8, sc, SERVER_COOKIE_LEN, now);
            }
        }
        (void)generate_server_cookie(NULL, "192.0.2.1", cc8, sc, now);
        (void)verify_server_cookie(NULL, "192.0.2.1", cc8, sc, SERVER_COOKIE_LEN, now);
        server_config_t c0; memset(&c0, 0, sizeof(c0));
        (void)generate_server_cookie(&c0, "192.0.2.1", cc8, sc, now);
        (void)verify_server_cookie(&c0, "192.0.2.1", cc8, sc, SERVER_COOKIE_LEN, now);
        uint8_t h[8], vr[8] = {1,0,0,0,0,0,0,0};
        (void)compute_server_cookie_hash(c.cookie_secrets[0], "2001:db8::9", cc8, vr, h);
        (void)compute_server_cookie_hash(c.cookie_secrets[0], "garbage", cc8, vr, h);
        (void)compute_server_cookie_hash(c.cookie_secrets[0], NULL, cc8, vr, h);
        init_server_cookie_secret();
        edns_info_t e; memset(&e, 0, sizeof(e));
        for (int i = 0; i < MAX_EDE_COUNT + 3; i++) add_ede(&e, true, (uint16_t)(i % 25), i & 1 ? "t" : NULL);
        add_ede(&e, false, 3, "x");
        e.present = true; e.ede_count = 0;
        for (int i = 0; i < MAX_EDE_COUNT + 3; i++) add_ede(&e, true, (uint16_t)(i % 25), i & 1 ? "t" : NULL);
    }
    /* ---- RRL ---- */
    {
        rrl_init();
        rate_limit_config_t rc; memset(&rc, 0, sizeof(rc));
        struct sockaddr_in s4 = { .sin_family = AF_INET }; struct sockaddr_in6 s6 = { .sin6_family = AF_INET6 };
        struct sockaddr sx = { .sa_family = AF_UNIX };
        bool slip;
        assert(rrl_check(&s4, RRL_RESP_NOERROR, NULL, &slip));
        assert(rrl_check(&s4, RRL_RESP_NOERROR, &rc, &slip));
        rc.configured = true;
        assert(rrl_check(NULL, RRL_RESP_NOERROR, &rc, &slip));
        assert(rrl_check(&s4, RRL_RESP_NOERROR, &rc, &slip));   /* rate 0: unlimited */
        rc.responses_per_second = 2; rc.nodata_per_second = 1; rc.nxdomains_per_second = 1; rc.errors_per_second = 1;
        rc.window_seconds = 1; rc.slip = 2;
        ip_port_t ex[2] = { { "192.0.2.0/24", 0 }, { "2001:db8:ff::/48", 0 } };
        cidr_entry_t exp[2]; cidr_entry_parse(&exp[0], ex[0].ip); cidr_entry_parse(&exp[1], ex[1].ip);
        for (int mode = 0; mode < 6; mode++) {
            rc.exempt_clients = mode == 1 || mode == 2 ? ex : NULL;
            rc.exempt_clients_count = mode == 1 || mode == 2 ? 2 : 0;
            rc.exempt_clients_parsed = mode == 2 ? exp : NULL;
            rc.log_only = mode == 3;
            rc.responses_per_second = mode == 4 ? 0xFFFFFFFFu : 2;
            rc.nodata_per_second = mode == 4 ? 0xFFFFFFFFu : 1;
            rc.nxdomains_per_second = mode == 4 ? 0xFFFFFFFFu : 1;
            rc.errors_per_second = mode == 4 ? 0xFFFFFFFFu : 1;
            rc.window_seconds = mode == 5 ? 0xFFFFFFFFu : 1;
            for (int i = 0; i < 3000; i++) {
                inet_pton(AF_INET, (i & 1) ? "192.0.2.9" : "198.51.100.9", &s4.sin_addr);
                s4.sin_addr.s_addr ^= htonl((uint32_t)(i / 16) << 8);
                s6.sin6_addr.s6_addr[0] = 0x20; s6.sin6_addr.s6_addr[1] = 0x01; s6.sin6_addr.s6_addr[2] = 0x0d; s6.sin6_addr.s6_addr[3] = 0xb8;
                s6.sin6_addr.s6_addr[4] = (i & 2) ? 0xff : (uint8_t)i; s6.sin6_addr.s6_addr[5] = (uint8_t)(i >> 8);
                rrl_response_class_t cl = (rrl_response_class_t)(i % 4);
                (void)rrl_check(&s4, cl, &rc, &slip);
                (void)rrl_check(&s6, cl, &rc, &slip);
                if ((i & 63) == 0) { (void)rrl_check(&sx, cl, &rc, &slip); (void)rrl_is_client_exhausted(&s4, &rc); (void)rrl_is_client_exhausted(&s6, &rc); }
            }
        }
        rc.configured = false; (void)rrl_is_client_exhausted(&s4, &rc); (void)rrl_is_client_exhausted(&s4, NULL);
        rc.configured = true; rc.responses_per_second = 0; (void)rrl_is_client_exhausted(&s4, &rc);
        uint8_t hb[12] = {0};
        (void)get_rrl_class(hb, 5); hb[3] = 3; (void)get_rrl_class(hb, 12); hb[3] = 0; (void)get_rrl_class(hb, 12);
        hb[7] = 1; (void)get_rrl_class(hb, 12); hb[3] = 2; (void)get_rrl_class(hb, 12);
        rrl_shutdown();
    }
    printf("  -> ECS/cookie/RRL helpers passed.\n");
}

/* dnstap: fake frame-stream receiver on a UNIX socket with scripted replies. */
static char g_dt_path[256];
static volatile int g_dt_scn;
static void *dt_server(void *arg) {
    int ls = *(int *)arg;
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) break;
        int scn = g_dt_scn;
        if (scn < 0) { close(c); break; }
        uint8_t buf[256]; (void)recv(c, buf, 42, MSG_WAITALL);
        uint32_t fr[3];
        switch (scn) {
        case 0: fr[0] = 0; fr[1] = htonl(4); fr[2] = htonl(1); break;       /* ACCEPT      */
        case 1: fr[0] = htonl(5); fr[1] = htonl(4); fr[2] = htonl(1); break;/* bad escape  */
        case 2: fr[0] = 0; fr[1] = htonl(2); fr[2] = 0; break;              /* len < 4     */
        case 3: fr[0] = 0; fr[1] = htonl(5000); fr[2] = 0; break;           /* len > 1024  */
        case 4: fr[0] = 0; fr[1] = htonl(4); fr[2] = htonl(9); break;       /* not ACCEPT  */
        default: close(c); continue;                                          /* hang up     */
        }
        if (scn == 5 + 1) { send(c, fr, 6, 0); close(c); continue; }
        send(c, fr, sizeof(fr), MSG_NOSIGNAL);
        uint8_t sink[4096]; while (recv(c, sink, sizeof(sink), 0) > 0) {}
        close(c);
    }
    return NULL;
}

static void test_dnstap_edges(void) {
    printf("[TEST] Sweep: dnstap handshake / frame writer...\n");
    snprintf(g_dt_path, sizeof(g_dt_path), "/tmp/kdt_%d.sock", (int)getpid());
    unlink(g_dt_path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun; memset(&sun, 0, sizeof(sun)); sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%.100s", g_dt_path);
    assert(bind(ls, (struct sockaddr *)&sun, sizeof(sun)) == 0 && listen(ls, 8) == 0);
    pthread_t t; pthread_create(&t, NULL, dt_server, &ls);
    assert(dnstap_connect_and_handshake(NULL, "i", "v") == -1);
    assert(dnstap_connect_and_handshake("", NULL, NULL) == -1);
    assert(dnstap_connect_and_handshake("/nonexistent/sock", NULL, NULL) == -1);
    for (int scn = 1; scn <= 6; scn++) { g_dt_scn = scn; int fd = dnstap_connect_and_handshake(g_dt_path, "id", "ver"); if (fd >= 0) close(fd); }
    g_dt_scn = 0;
    int fd = dnstap_connect_and_handshake(g_dt_path, "sweep-identity", "sweep-version");
    uint8_t wire[64] = { 0x12, 0x34, 0x81, 0x80 }, scratch[70000];
    struct sockaddr_in c4 = { .sin_family = AF_INET, .sin_port = htons(5353) };
    struct sockaddr_in6 c6 = { .sin6_family = AF_INET6, .sin6_port = htons(5353) };
    struct sockaddr_in6 s6 = { .sin6_family = AF_INET6, .sin6_port = htons(53) };
    struct sockaddr_in6 s6z = { .sin6_family = AF_INET6, .sin6_port = 0 };
    dnstap_event_meta_t m; uint8_t dst[128]; size_t wl;
    const void *cls[] = { &c4, &c6, NULL };
    const socklen_t cll[] = { sizeof(c4), sizeof(c6), 0 };
    const void *srv[] = { &c4, &s6, &s6z, NULL };
    int prev = g_dnstap_sock;
    g_dnstap_sock = fd;
    for (int ci = 0; ci < 3; ci++) for (int si = 0; si < 4; si++) for (int mt = 1; mt <= 2; mt++) {
        fill_dnstap_event(&m, dst, sizeof(dst), &wl, (uint8_t)mt, wire, sizeof(wire), cls[ci], cll[ci], srv[si], si != 3, (uint8_t)(mt == 1 ? IPPROTO_UDP : IPPROTO_TCP));
        (void)dnstap_send_frame(&m, dst, wl, scratch, sizeof(scratch));
        (void)dnstap_build_message(&m, wire, sizeof(wire), scratch, 10);
    }
    fill_dnstap_event(&m, dst, 4, &wl, 1, wire, sizeof(wire), &c4, sizeof(c4), NULL, false, IPPROTO_UDP);
    if (fd >= 0) close(fd);
    g_dnstap_sock = -1;
    assert(!dnstap_send_frame(&m, dst, wl, scratch, sizeof(scratch)));
    int pp[2]; assert(pipe(pp) == 0); close(pp[0]);
    g_dnstap_sock = pp[1];
    (void)dnstap_send_frame(&m, dst, wl, scratch, sizeof(scratch));     /* EPIPE */
    close(pp[1]);
    g_dnstap_sock = prev;
    g_dt_scn = -1;
    int k = socket(AF_UNIX, SOCK_STREAM, 0); connect(k, (struct sockaddr *)&sun, sizeof(sun)); close(k);
    pthread_join(t, NULL);
    close(ls); unlink(g_dt_path);
    printf("  -> dnstap edges passed.\n");
}

/* ===========================================================================
 * RFC 2136 UPDATE matrix: every prerequisite form x every update form, each
 * packet also replayed truncated at every length.
 * ======================================================================== */
typedef struct { const char *name; uint16_t type, cls; uint32_t ttl; const uint8_t *rd; uint16_t rdlen; } urr_t;

static size_t upd_build(uint8_t *p, const char *zone, const urr_t *pre, int npre, const urr_t *up, int nup) {
    memset(p, 0, 12);
    p[0] = 0x55; p[1] = 0xAA; p[2] = 0x28;
    p[5] = 1; p[7] = (uint8_t)npre; p[9] = (uint8_t)nup;
    size_t o = 12 + (size_t)write_uncompressed_name(p, 12, 512, zone);
    p[o++] = 0; p[o++] = 6; p[o++] = 0; p[o++] = 1;
    const urr_t *sets[2] = { pre, up }; int ns[2] = { npre, nup };
    for (int s2 = 0; s2 < 2; s2++) for (int i = 0; i < ns[s2]; i++) {
        const urr_t *r = &sets[s2][i];
        o += (size_t)write_uncompressed_name(p, o, 1024, r->name);
        p[o++] = (uint8_t)(r->type >> 8); p[o++] = (uint8_t)r->type;
        p[o++] = (uint8_t)(r->cls >> 8); p[o++] = (uint8_t)r->cls;
        p[o++] = (uint8_t)(r->ttl >> 24); p[o++] = (uint8_t)(r->ttl >> 16); p[o++] = (uint8_t)(r->ttl >> 8); p[o++] = (uint8_t)r->ttl;
        p[o++] = (uint8_t)(r->rdlen >> 8); p[o++] = (uint8_t)r->rdlen;
        if (r->rdlen) { memcpy(p + o, r->rd, r->rdlen); o += r->rdlen; }
    }
    return o;
}

static void upd_entry_init(zone_db_entry_t *e) {
    static const char *zt =
        "$ORIGIN upd.example.\n$TTL 300\n@ IN SOA ns.upd.example. h.upd.example. 100 7200 3600 1209600 300\n"
        "@ IN NS ns.upd.example.\n@ IN NS ns2.other.test.\nns IN A 192.0.2.53\nns IN AAAA 2001:db8::53\n"
        "www IN A 192.0.2.80\nwww IN A 192.0.2.81\nwww IN TXT \"t\"\nalias IN CNAME www.upd.example.\n"
        "mx IN MX 10 www.upd.example.\n";
    memset(e, 0, sizeof(*e));
    strcpy(e->domain, "upd.example."); strcpy(e->view_name, "default");
    pthread_mutex_init(&e->writer_lock, NULL);
    pthread_mutex_init(&e->ixfr_history.lock, NULL);
    for (int k = 0; k < 2; k++) {
        zone_arena_t *a = k ? &e->rcu.arena_b : &e->rcu.arena_a;
        zone_arena_init(a);
        parse_error_t err = {0};
        parse_context_t ctx = { .base_dir = ".", .default_origin = "upd.example.", .is_standalone_mode = true, .err_out = &err };
        char *b = arena_strdup(a, zt);
        assert(parse_zone_fast(b, strlen(b), a, &ctx) >= 0);
        assert(build_zone_index(a, true) == 0);
    }
    atomic_store_explicit(&e->rcu.active, &e->rcu.arena_a, memory_order_release);
    atomic_store_explicit(&e->serial, 100, memory_order_release);
}

static void upd_entry_free(zone_db_entry_t *e) {
    zone_arena_destroy(&e->rcu.arena_a); zone_arena_destroy(&e->rcu.arena_b);
    for (int i = 0; i < e->ixfr_history.count; i++) {
        (void)i;
    }
    pthread_mutex_destroy(&e->writer_lock);
}

static void test_update_matrix(void) {
    printf("[TEST] Sweep: RFC 2136 UPDATE prerequisite x operation matrix...\n");
    static const uint8_t ip80[4] = { 192, 0, 2, 80 }, ip99[4] = { 192, 0, 2, 99 }, ip6[16] = { 0x20, 1, 0xd, 0xb8, [15] = 9 };
    static const uint8_t txt[3] = { 2, 'h', 'i' }, cname[] = { 3, 'w', 'w', 'w', 3, 'u', 'p', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    static const uint8_t soa[] = { 2,'n','s',0, 1,'h',0, 0,0,0,200, 0,0,0,1, 0,0,0,1, 0,0,0,1, 0,0,0,1 };
    static const uint8_t soa_old[] = { 2,'n','s',0, 1,'h',0, 0,0,0,50, 0,0,0,1, 0,0,0,1, 0,0,0,1, 0,0,0,1 };
    const urr_t pres[] = {
        { "www.upd.example.", 255, 255, 0, NULL, 0 },  /* name in use            */
        { "nx.upd.example.", 255, 255, 0, NULL, 0 },
        { "www.upd.example.", 1, 255, 0, NULL, 0 },    /* RRset exists (value-independent) */
        { "www.upd.example.", 28, 255, 0, NULL, 0 },
        { "nx.upd.example.", 255, 254, 0, NULL, 0 },   /* name not in use       */
        { "www.upd.example.", 255, 254, 0, NULL, 0 },
        { "www.upd.example.", 28, 254, 0, NULL, 0 },   /* RRset does not exist  */
        { "www.upd.example.", 1, 254, 0, NULL, 0 },
        { "www.upd.example.", 1, 1, 0, ip80, 4 },      /* value-dependent       */
        { "www.upd.example.", 1, 1, 0, ip99, 4 },
        { "www.upd.example.", 1, 255, 0, ip80, 4 },    /* rdlen != 0 with ANY -> FORMERR */
        { "www.upd.example.", 1, 255, 5, NULL, 0 },    /* ttl != 0 -> FORMERR   */
        { "out.of.zone.", 1, 255, 0, NULL, 0 },        /* NOTZONE               */
        { "www.upd.example.", 1, 3, 0, NULL, 0 },      /* bad class             */
    };
    const urr_t ups[] = {
        { "new.upd.example.", 1, 1, 300, ip99, 4 },
        { "new.upd.example.", 28, 1, 300, ip6, 16 },
        { "www.upd.example.", 1, 1, 300, ip80, 4 },     /* duplicate add         */
        { "www.upd.example.", 16, 1, 60, txt, 3 },
        { "alias.upd.example.", 1, 1, 300, ip99, 4 },   /* A next to CNAME       */
        { "www.upd.example.", 5, 1, 300, cname, sizeof(cname) }, /* CNAME next to data */
        { "alias.upd.example.", 5, 1, 300, cname, sizeof(cname) },
        { "upd.example.", 6, 1, 300, soa, sizeof(soa) },          /* SOA with newer serial */
        { "upd.example.", 6, 1, 300, soa_old, sizeof(soa_old) },  /* SOA with older serial */
        { "www.upd.example.", 1, 255, 0, NULL, 0 },     /* delete RRset          */
        { "www.upd.example.", 255, 255, 0, NULL, 0 },   /* delete all RRsets     */
        { "upd.example.", 255, 255, 0, NULL, 0 },       /* delete all at apex    */
        { "upd.example.", 2, 255, 0, NULL, 0 },         /* delete apex NS        */
        { "upd.example.", 6, 255, 0, NULL, 0 },         /* delete SOA (ignored)  */
        { "www.upd.example.", 1, 254, 0, ip80, 4 },     /* delete one RR         */
        { "upd.example.", 2, 254, 0, cname, sizeof(cname) },
        { "www.upd.example.", 255, 1, 300, NULL, 0 },   /* ANY type add -> FORMERR */
        { "www.upd.example.", 252, 1, 300, NULL, 0 },   /* AXFR meta type        */
        { "www.upd.example.", 1, 255, 300, NULL, 0 },   /* delete with ttl       */
        { "www.upd.example.", 1, 254, 5, ip80, 4 },
        { "out.of.zone.", 1, 1, 300, ip99, 4 },
        { "www.upd.example.", 1, 3, 300, ip99, 4 },     /* CH class              */
        { "www.upd.example.", 1, 1, 0x80000000u, ip99, 4 },
        { "bad.upd.example.", 1, 1, 300, ip99, 3 },     /* short A rdata         */
    };
    uint8_t pkt[2048];
    int results[16] = {0};
    for (size_t pi = 0; pi <= NELEM(pres); pi++) {
        for (size_t ui = 0; ui < NELEM(ups); ui++) {
            zone_db_entry_t e; upd_entry_init(&e);
            size_t len = upd_build(pkt, "upd.example.", pi < NELEM(pres) ? &pres[pi] : NULL, pi < NELEM(pres) ? 1 : 0, &ups[ui], 1);
            int rc = handle_dynamic_update(pkt, len, &e, "192.0.2.1", (pi & 1) ? "key" : NULL);
            if (rc >= 0 && rc < 16) results[rc]++;
            upd_entry_free(&e);
        }
    }
    /* multi-record updates and truncations */
    zone_db_entry_t e; upd_entry_init(&e);
    size_t len = upd_build(pkt, "upd.example.", pres, 3, ups, 8);
    for (size_t cut = 0; cut <= len; cut++) (void)handle_dynamic_update(pkt, cut, &e, "192.0.2.1", NULL);
    for (size_t pos = 12; pos < len; pos += 1) {
        uint8_t m[2048]; memcpy(m, pkt, len); m[pos] ^= 0xFF;
        (void)handle_dynamic_update(m, len, &e, "192.0.2.1", NULL);
    }
    len = upd_build(pkt, "other.zone.", NULL, 0, ups, 1);            /* zone section mismatch */
    (void)handle_dynamic_update(pkt, len, &e, "192.0.2.1", NULL);
    pkt[5] = 2; (void)handle_dynamic_update(pkt, len, &e, "192.0.2.1", NULL);   /* ZOCOUNT != 1 */
    len = upd_build(pkt, "upd.example.", NULL, 0, ups, 1); pkt[len - 16] = 0; /* zone type not SOA */
    (void)handle_dynamic_update(pkt, len, &e, "192.0.2.1", NULL);
    (void)bump_soa_serial_in_arena(&e.rcu.arena_a, "upd.example.");
    (void)bump_soa_serial_in_arena(&e.rcu.arena_a, "nomatch.example.");
    upd_entry_free(&e);
    printf("  -> UPDATE matrix passed (NOERROR=%d FORMERR=%d NXDOMAIN=%d YXDOMAIN=%d YXRRSET=%d NXRRSET=%d NOTZONE=%d).\n",
           results[0], results[1], results[3], results[6], results[7], results[8], results[10]);
}

/* ===========================================================================
 * AXFR / IXFR server <-> secondary round trips: plain, extended (option 65153),
 * IXFR from every historical serial, TSIG-signed, and damaged streams.
 * ======================================================================== */
static void xfr_entry_init(zone_db_entry_t *e, const char *text, const char *origin) {
    memset(e, 0, sizeof(*e));
    snprintf(e->domain, sizeof(e->domain), "%s", origin); strcpy(e->view_name, "default");
    pthread_mutex_init(&e->writer_lock, NULL);
    pthread_mutex_init(&e->ixfr_history.lock, NULL);
    for (int k = 0; k < 2; k++) {
        zone_arena_t *a = k ? &e->rcu.arena_b : &e->rcu.arena_a;
        zone_arena_init(a);
        if (!text) continue;
        parse_error_t err = {0};
        parse_context_t ctx = { .base_dir = ".", .default_origin = origin, .is_standalone_mode = true, .err_out = &err };
        char *b = arena_strdup(a, text);
        assert(parse_zone_fast(b, strlen(b), a, &ctx) >= 0);
        assert(build_zone_index(a, true) == 0);
    }
    atomic_store_explicit(&e->rcu.active, &e->rcu.arena_a, memory_order_release);
}

static size_t xfr_req(uint8_t *p, uint16_t qtype, int serial, bool ext, const char *dom, tsig_key_t *k, uint8_t *mac, size_t *maclen) {
    memset(p, 0, 12); p[0] = 0x0A; p[1] = 0xF0; p[5] = 1;
    size_t o = 12 + (size_t)write_uncompressed_name(p, 12, 300, dom);
    p[o++] = (uint8_t)(qtype >> 8); p[o++] = (uint8_t)qtype; p[o++] = 0; p[o++] = 1;
    if (serial >= 0) {
        p[9] = 1;
        o += (size_t)write_uncompressed_name(p, o, 600, dom);
        p[o++] = 0; p[o++] = 6; p[o++] = 0; p[o++] = 1; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0;
        p[o++] = 0; p[o++] = 22; p[o++] = 0; p[o++] = 0;          /* root mname + root rname */
        p[o++] = (uint8_t)(serial >> 24); p[o++] = (uint8_t)(serial >> 16); p[o++] = (uint8_t)(serial >> 8); p[o++] = (uint8_t)serial;
        memset(p + o, 0, 16); o += 16;
    }
    if (ext) {
        p[11] = 1;
        uint32_t h = calc_fnv1a_str(dom);
        p[o++] = 0; p[o++] = 0; p[o++] = 41; p[o++] = 16; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0;
        p[o++] = 0; p[o++] = 9;
        p[o++] = 0xFE; p[o++] = 0x81; p[o++] = 0; p[o++] = 5; p[o++] = 1;
        p[o++] = (uint8_t)(h >> 24); p[o++] = (uint8_t)(h >> 16); p[o++] = (uint8_t)(h >> 8); p[o++] = (uint8_t)h;
    }
    if (k) { *maclen = 64; assert(tsig_sign_packet(p, &o, 4096, k, 0, mac, maclen, NULL, 0, false) == 0); }
    return o;
}

static void xfr_replay(const uint8_t *stream, size_t len, const char *dom, const char *sec_text,
                       bool ixfr, uint32_t cserial, tsig_key_t *k, const uint8_t *mac, size_t maclen) {
    /* (a) packet parser directly */
    zone_arena_t standby, active; memset(&standby, 0, sizeof(standby)); memset(&active, 0, sizeof(active));
    zone_arena_init(&standby); zone_arena_init(&active);
    axfr_session_t ss; memset(&ss, 0, sizeof(ss)); ss.is_ixfr = ixfr; ss.client_serial = cserial;
    size_t o = 0;
    while (o + 2 <= len) {
        size_t ml = ((size_t)stream[o] << 8) | stream[o + 1];
        if (o + 2 + ml > len) break;
        if (parse_xfr_packet(stream + o + 2, ml, &standby, &active, &ss, dom) < 0) break;
        o += 2 + ml;
    }
    zone_arena_destroy(&standby); zone_arena_destroy(&active);
    /* (b) full secondary pipeline over a socketpair */
    zone_db_entry_t sec; xfr_entry_init(&sec, sec_text, dom);
    int sp[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    int one = 1 << 22; setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF, &one, sizeof(one)); setsockopt(sp[1], SOL_SOCKET, SO_RCVBUF, &one, sizeof(one));
    pid_t pid = fork();
    if (pid == 0) wd_child();
    if (pid == 0) { close(sp[1]); size_t w = 0; while (w < len) { ssize_t n = write(sp[0], stream + w, len - w); if (n <= 0) break; w += (size_t)n; } close(sp[0]); _exit(0); }
    close(sp[0]);
    tcp_stream_ctx_t sc; memset(&sc, 0, sizeof(sc));
    axfr_session_t s2; memset(&s2, 0, sizeof(s2)); s2.is_ixfr = ixfr; s2.client_serial = cserial;
    int hrc = handle_axfr_event(sp[1], &sec, &sc, &s2, k, mac, maclen);
    if (getenv("SW_SYSLOG")) fprintf(stderr, "XFRDBG len=%zu ixfr=%d hrc=%d parsed_upto=%zu\n", len, ixfr, hrc, o);
    close(sp[1]);
    waitpid(pid, NULL, 0);
    zone_arena_destroy(&sec.rcu.arena_a); zone_arena_destroy(&sec.rcu.arena_b);
    for (int i = 0; i < MAX_IXFR_HISTORY; i++) if (sec.ixfr_history.entries[i]) { free_ixfr_txn(sec.ixfr_history.entries[i]); sec.ixfr_history.entries[i] = NULL; }
}

static void test_xfr_roundtrips(void) {
    printf("[TEST] Sweep: AXFR/IXFR server->secondary round trips...\n");
    const char *dom = "xfr.example.";
    size_t cap = 400000; char *zt = malloc(cap);
    size_t o = (size_t)snprintf(zt, cap,
        "$ORIGIN xfr.example.\n$TTL 300\n$LOCATION-TAG office 10.0.0.0/8\n$ECS-SUBNET-TAG eu 198.51.100.0/24\n"
        "@ IN SOA ns.xfr.example. h.xfr.example. 100 7200 3600 1209600 300\n@ IN NS ns.xfr.example.\nns IN A 192.0.2.1\n"
        "g IN TYPE65000 \\# 3 010203\nh IN HINFO \"a\" \"b\"\n"
        "$LOCATION office\nloc IN A 10.0.0.1\n$LOCATION default\n$ECS-SUBNET eu\necs IN A 198.51.100.1\n$ECS-SUBNET default\n");
    for (int i = 0; i < 2500; i++) o += (size_t)snprintf(zt + o, cap - o, "t%d IN TXT \"%060d\"\n", i, i);
    zone_db_entry_t srv; xfr_entry_init(&srv, zt, dom);
    atomic_store_explicit(&srv.serial, 100, memory_order_release);
    /* tinydns-style metadata on a couple of records so the wrap path is used */
    zone_arena_t *act = atomic_load_explicit(&srv.rcu.active, memory_order_acquire);
    for (size_t i = 0; i < act->count && i < 40; i++) if (act->records[i].type_code == 16 && (i & 1)) { act->records[i].tinydns_loc[0] = 'j'; act->records[i].tinydns_loc[1] = 'p'; }
    /* build IXFR history with a few updates (serial 100 -> 104) */
    for (int u = 0; u < 4; u++) {
        char nm[64]; snprintf(nm, sizeof(nm), "u%d.xfr.example.", u);
        static const uint8_t ip[4] = { 192, 0, 2, 44 };
        urr_t add = { nm, 1, 1, 300, ip, 4 };
        urr_t del = { "t1.xfr.example.", 16, 255, 0, NULL, 0 };
        uint8_t up[1024]; size_t ul = upd_build(up, dom, NULL, 0, u == 2 ? &del : &add, 1);
        (void)handle_dynamic_update(up, ul, &srv, "127.0.0.1", NULL);
    }
    const char *sec_old =
        "$ORIGIN xfr.example.\n@ 300 IN SOA ns.xfr.example. h.xfr.example. 101 7200 3600 1209600 300\n@ 300 IN NS ns.xfr.example.\n";
    tsig_key_t k; memset(&k, 0, sizeof(k)); k.name = "xfr-key."; k.algorithm = "hmac-sha256";
    memset(k.secret_decoded, 7, 32); k.secret_decoded_len = 32;
    struct sockaddr_storage ca; memset(&ca, 0, sizeof(ca)); ca.ss_family = AF_INET;
    struct { uint16_t qt; int serial; bool ext; bool tsig; } rq[] = {
        { 252, -1, false, false }, { 252, -1, true, false }, { 252, -1, false, true }, { 252, -1, true, true },
        { 251, 100, false, false }, { 251, 101, false, false }, { 251, 102, false, true }, { 251, 104, false, false },
        { 251, 50, false, false }, { 251, 200, false, false }, { 251, 101, true, false }, { 251, -1, false, false },
    };
    uint8_t req[4096], mac[64];
    for (size_t r = 0; r < NELEM(rq); r++) {
        size_t maclen = 0;
        size_t rl = xfr_req(req, rq[r].qt, rq[r].serial, rq[r].ext, dom, rq[r].tsig ? &k : NULL, mac, &maclen);
        g_cap_len = 0; g_cap_on = true;
        send_axfr_response(-1, dom, req, (uint16_t)rl, rq[r].tsig ? &k : NULL, &srv, rq[r].tsig ? mac : NULL, maclen,
                           &ca, sizeof(struct sockaddr_in), &ca, r & 1);
        g_cap_on = false;
        size_t cl = g_cap_len;
        uint8_t *stream = malloc(cl + 1); memcpy(stream, g_cap, cl);
        bool ix = rq[r].qt == 251;
        xfr_replay(stream, cl, dom, sec_old, ix, ix ? (uint32_t)(rq[r].serial < 0 ? 0 : rq[r].serial) : 0,
                   rq[r].tsig ? &k : NULL, mac, maclen);
        if (r == 0 || r == 2 || r == 6) {
            /* damaged streams: truncated at a few points, and a flipped byte */
            size_t cuts[] = { 2, 20, cl / 3, cl - 1 };
            for (size_t c = 0; c < NELEM(cuts); c++) if (cuts[c] < cl)
                xfr_replay(stream, cuts[c], dom, sec_old, ix, (uint32_t)(rq[r].serial < 0 ? 0 : rq[r].serial), rq[r].tsig ? &k : NULL, mac, maclen);
            stream[40] ^= 0x55;
            xfr_replay(stream, cl, dom, sec_old, ix, 0, rq[r].tsig ? &k : NULL, mac, maclen);
            xfr_replay(stream, cl, dom, NULL, ix, 0, NULL, NULL, 0);            /* TSIG expected but absent / vice versa */
        }
        free(stream);
        /* broken client connection while streaming */
        send_axfr_response(-2, dom, req, (uint16_t)rl, NULL, &srv, NULL, 0, &ca, sizeof(struct sockaddr_in), NULL, false);
    }
    /* no entry / empty zone / zone without SOA */
    size_t rl = xfr_req(req, 252, -1, false, dom, NULL, mac, NULL);
    send_axfr_response(-1, dom, req, (uint16_t)rl, NULL, NULL, NULL, 0, &ca, sizeof(struct sockaddr_in), NULL, false);
    zone_db_entry_t empty; xfr_entry_init(&empty, NULL, dom);
    send_axfr_response(-1, dom, req, (uint16_t)rl, NULL, &empty, NULL, 0, &ca, sizeof(struct sockaddr_in), NULL, false);
    zone_db_entry_t nosoa; xfr_entry_init(&nosoa, "$ORIGIN xfr.example.\n@ 60 IN NS ns\nns 60 IN A 192.0.2.1\n", dom);
    send_axfr_response(-1, dom, req, (uint16_t)rl, NULL, &nosoa, NULL, 0, &ca, sizeof(struct sockaddr_in), NULL, false);
    send_axfr_response(-1, dom, req, 14, NULL, &srv, NULL, 0, &ca, sizeof(struct sockaddr_in), NULL, false);   /* short question */
    assert(wait_for_active_axfr(&srv, 10));
    atomic_store_explicit(&srv.active_axfr, 1, memory_order_release);
    assert(!wait_for_active_axfr(&srv, 20));
    atomic_store_explicit(&srv.active_axfr, 0, memory_order_release);
    zone_arena_destroy(&empty.rcu.arena_a); zone_arena_destroy(&empty.rcu.arena_b);
    zone_arena_destroy(&nosoa.rcu.arena_a); zone_arena_destroy(&nosoa.rcu.arena_b);
    zone_arena_destroy(&srv.rcu.arena_a); zone_arena_destroy(&srv.rcu.arena_b);
    for (int i = 0; i < MAX_IXFR_HISTORY; i++) if (srv.ixfr_history.entries[i]) free_ixfr_txn(srv.ixfr_history.entries[i]);
    free(zt); free(g_cap); g_cap = NULL; g_cap_cap = 0;
    printf("  -> AXFR/IXFR round trips passed.\n");
}

/* ===========================================================================
 * named.conf parser: a configuration using every statement, parsed after
 * deleting / replacing each token in turn and after truncation at every token.
 * ======================================================================== */
static const char *CONF_RICH =
    "# hash comment\n// line comment\n/* block\n comment */\n"
    "options { directory \"/tmp\"; port 5300; user \"nobody\"; group \"nogroup\"; pid-file \"none\";\n"
    "  bind-address { 127.0.0.1; ::1; 0.0.0.0 port 53; };\n"
    "  udp-recvbuf-size 4M; udp-sndbuf-size 512K; query-log-max-qps 10; query-log-buffer-size 1024;\n"
    "  rate-limit { responses-per-second 5; nodata-per-second 5; nxdomains-per-second 5; errors-per-second 5;\n"
    "    window 15; slip 2; log-only yes; early-drop yes; exempt-clients { 127.0.0.1/32; ::1/128; }; };\n"
    "  ecs-enable yes; ecs-trusted-resolvers { 127.0.0.1; 10.0.0.0/8; };\n"
    "  ecs-tags { tag \"eu\" { 198.51.100.0/24; 2001:db8::/32; }; tag \"us\" { 203.0.113.0/24; }; };\n"
    "  location-tags { tag \"office\" { 10.0.0.0/8; }; };\n"
    "  send-extended-errors yes; serve-stale no; rfc10029-mqtype yes; tcp-connection-reuse yes;\n"
    "  tcp-idle-timeout 30000; cookie-secret \"000102030405060708090a0b0c0d0e0f\"; cookie-algorithm \"siphash-2-4\";\n"
    "  nsid \"ns-a\"; minimal-responses yes; minimal-any yes; additional-from-auth in-domain;\n"
    "  allow-program-zones yes; max-mqtypes 3; minimal-any-ttl 60; wire-cache-max-records 100;\n"
    "  dnstap { socket \"/tmp/dnstap.sock\"; identity \"id\"; version \"v\"; };\n"
    "};\n"
    "logging { channel q { file \"/tmp/q.log\" versions 3 size 10M; print-time yes; print-category yes; print-severity yes; };\n"
    "  channel d { file \"/tmp/d.log\" versions 2 suffix timestamp; severity info; };\n"
    "  channel s { syslog daemon; }; category queries { q; }; category default { d; s; }; };\n"
    "control-channel { socket \"/tmp/ctl.sock\"; algorithm \"hmac-sha256\"; secret \"c2VjcmV0c2VjcmV0c2VjcmV0\"; };\n"
    "key \"k1\" { algorithm \"hmac-sha256\"; secret \"c2VjcmV0c2VjcmV0c2VjcmV0\"; };\n"
    "key \"k2\" { algorithm hmac-md5; secret \"c2VjcmV0\"; };\n"
    "acl \"trusted\" { 127.0.0.1; 10.0.0.0/8; !192.0.2.0/24; key k1; };\n"
    "view \"inside\" { match-clients { trusted; 10.0.0.0/8; };\n"
    "  zone \"a.example\" { type master; file \"/tmp/a.zone\"; allow-transfer { key k1; 127.0.0.1; }; allow-update { key k1; };\n"
    "    also-notify { 192.0.2.1 port 5353; 2001:db8::1; }; notify-source \"192.0.2.9\"; ecs-tags { tag \"z\" { 192.0.2.0/24; }; };\n"
    "    location-tags { tag \"l\" { 10.1.0.0/16; }; }; ecs-trusted-resolvers { 127.0.0.1; }; additional-from-auth no;\n"
    "    rate-limit { responses-per-second 1; }; file-format \"text\"; };\n"
    "  zone \"s.example\" { type slave; file \"/tmp/s.zone\"; masters { 192.0.2.53 port 53 key k1; 2001:db8::53; }; tsig-key \"k1\"; };\n"
    "  zone \"t.example\" { type master; file \"/tmp/t.data\"; file-format \"tinydns\"; };\n"
    "  zone \"c.example\" { type master; file \"/tmp/c.zone\"; catalog-zone yes; };\n"
    "  zone \"p.example\" { type program; program \"/bin/cat\"; program-args { \"-u\"; \"x\"; }; program-user \"nobody\";\n"
    "    program-timeout 500; program-max-failures 3; disable-auto-tc-flag no; };\n"
    "  zone \"f.example\" { type forward; forwarders { 192.0.2.1; 192.0.2.2 port 5353; }; forward-timeout 800; };\n"
    "};\n"
    "view \"outside\" { match-clients { any; }; zone \"a.example\" { type master; file \"/tmp/a.zone\"; }; };\n";

static int conf_parse_one(const char *text) {
    server_config_t *c = calloc(1, sizeof(*c));
    int rc = parse_named_conf(text, c);
    free_server_config_fields(c); free(c);
    return rc;
}

static void test_config_sweep(void) {
    printf("[TEST] Sweep: named.conf token deletion / replacement / truncation...\n");
    (void)conf_parse_one(CONF_RICH);
    /* tokenize on whitespace */
    size_t n = strlen(CONF_RICH);
    size_t starts[4096], ends[4096]; size_t nt = 0;
    for (size_t i = 0; i < n && nt < 4096;) {
        while (i < n && (CONF_RICH[i] == ' ' || CONF_RICH[i] == '\n')) i++;
        if (i >= n) break;
        starts[nt] = i;
        while (i < n && CONF_RICH[i] != ' ' && CONF_RICH[i] != '\n') i++;
        ends[nt++] = i;
    }
    static const char *rep[] = { "", "{", "}", ";", "\"x\"", "-1", "99999999999", "yes", "bogus", "\"" };
    char *buf = malloc(n + 64);
    for (size_t t = 0; t < nt; t++) {
        for (size_t r = 0; r < NELEM(rep); r++) {
            if (r > 1 && (t % 3) != 0) continue;           /* full replacement set on every third token */
            size_t o = 0;
            memcpy(buf + o, CONF_RICH, starts[t]); o += starts[t];
            size_t rl = strlen(rep[r]); memcpy(buf + o, rep[r], rl); o += rl;
            memcpy(buf + o, CONF_RICH + ends[t], n - ends[t]); o += n - ends[t];
            buf[o] = 0;
            (void)conf_parse_one(buf);
        }
        memcpy(buf, CONF_RICH, ends[t]); buf[ends[t]] = 0;     /* truncated after this token */
        (void)conf_parse_one(buf);
    }
    free(buf);
    /* lexer corner cases */
    char big[6000]; memset(big, 'a', sizeof(big)); big[0] = '"'; big[sizeof(big) - 1] = 0;
    const char *odd[] = { "", "/* unterminated", "options { directory \"unterminated", "options { port 1; }; /* x */ # y\n",
        "options { directory \"a\\\"b\"; };", "include;", "include \"/nonexistent/x.conf\";", "include \"\";",
        "options { include \"/nonexistent\"; };", "zone { };", "zone \"x\" { type master; file; };", "view { };",
        "key \"k\" { algorithm; };", "acl x { 1.2.3.4/99; };", "options { bind-address { 1.2.3.4 port x; }; };",
        "options { udp-recvbuf-size 9999999999G; };", "options { tcp-idle-timeout -5; };", "options { cookie-secret \"zz\"; };",
        "options { cookie-secret \"000102030405060708090a0b0c0d0e0f\"; cookie-secret \"000102030405060708090a0b0c0d0e0f\"; cookie-secret \"000102030405060708090a0b0c0d0e0f\"; cookie-secret \"000102030405060708090a0b0c0d0e0f\"; cookie-secret \"000102030405060708090a0b0c0d0e0f\"; };",
        "options { max-mqtypes 0; minimal-any-ttl x; wire-cache-max-records -1; };",
        "logging { channel c { file \"x\" versions unlimited size 1G; }; category x { c; }; };",
        "logging { channel c { file \"x\" versions -1 size 0; }; };", "logging { channel c { bogus; }; };",
        "zone \"a\" { type master; file \"x\"; }; zone \"a\" { type master; file \"x\"; };",
        "view \"v\" { zone \"a\" { type master; file \"x\"; }; }; zone \"b\" { type master; file \"y\"; };",
        "}", "{", ";", "\"a\" \"b\"", big };
    for (size_t i = 0; i < NELEM(odd); i++) (void)conf_parse_one(odd[i]);
    char path[300]; snprintf(path, sizeof(path), "%s/inc.conf", g_sdir[0] ? g_sdir : "/tmp");
    FILE *f = fopen(path, "w");
    if (f) {
        fputs("key \"ik\" { algorithm \"hmac-sha256\"; secret \"c2VjcmV0\"; };\ninclude \"inc.conf\";\n", f); fclose(f);
        char txt[600]; snprintf(txt, sizeof(txt), "include \"%s\";\noptions { include \"inc.conf\"; };\n", path);
        server_config_t *c = calloc(1, sizeof(*c));
        (void)parse_named_conf_ext(txt, path, c);
        free_server_config_fields(c); free(c);
        unlink(path);
    }
    printf("  -> config sweeps passed.\n");
}

/* ===========================================================================
 * NOTIFY / UPDATE / UDP-IXFR through process_dns_query_impl(): master vs slave
 * zones, masters ACLs, zone TSIG keys, allow-update by address and by key,
 * signed with the right key / another key / an unknown key / a broken MAC.
 * ======================================================================== */
static const char *CONF_OPS =
    "options { directory \".\"; rate-limit { responses-per-second 1; errors-per-second 1; nxdomains-per-second 1;\n"
    "  nodata-per-second 1; early-drop yes; slip 2; exempt-clients { 127.0.0.2; }; }; send-extended-errors yes;\n"
    "  allow-program-zones yes; };\n"
    "key \"k1\" { algorithm \"hmac-sha256\"; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0\"; };\n"
    "key \"k2\" { algorithm \"hmac-sha1\"; secret \"b3RoZXJvdGhlcm90aGVy\"; };\n"
    "view \"default\" { match-clients { any; };\n"
    "  zone \"example.\" { type master; file \"x\"; allow-update { key k1; 192.0.2.100; }; };\n"
    "  zone \"n3.example.\" { type slave; file \"y\"; masters { 192.0.2.100; 10.0.0.0/8; }; tsig-key \"k1\"; };\n"
    "  zone \"other.test.\" { type master; file \"z\"; allow-update { 10.1.2.3; key k2; };\n"
    "      rate-limit { responses-per-second 2; early-drop yes; }; };\n"
    "  zone \"geo.test.\" { type slave; file \"g\"; masters { 127.0.0.1; }; };\n"
    "  zone \"nosoa.test.\" { type program; program \"/bin/cat\"; };\n"
    "};\n";

static size_t op_build(uint8_t *p, uint8_t opcode, const char *zone, uint16_t qtype, int soa_serial, bool tc) {
    memset(p, 0, 12);
    p[0] = 0x77; p[1] = (uint8_t)(opcode * 16 + qtype);
    p[2] = (uint8_t)((opcode << 3) | (tc ? 0x02 : 0) | (opcode == 4 ? 0x04 : 0));
    p[5] = 1;
    size_t o = 12 + (size_t)write_uncompressed_name(p, 12, 300, zone);
    p[o++] = (uint8_t)(qtype >> 8); p[o++] = (uint8_t)qtype; p[o++] = 0; p[o++] = 1;
    if (soa_serial >= 0) {
        if (opcode == 4) p[7] = 1; else p[9] = 1;
        o += (size_t)write_uncompressed_name(p, o, 600, zone);
        p[o++] = 0; p[o++] = 6; p[o++] = 0; p[o++] = 1; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 60;
        p[o++] = 0; p[o++] = 22; p[o++] = 0; p[o++] = 0;
        p[o++] = (uint8_t)(soa_serial >> 24); p[o++] = (uint8_t)(soa_serial >> 16); p[o++] = (uint8_t)(soa_serial >> 8); p[o++] = (uint8_t)soa_serial;
        memset(p + o, 0, 16); o += 16;
    }
    if (opcode == 5) {   /* one UPDATE RR: add A record */
        p[9] = 1;
        char nm[300]; snprintf(nm, sizeof(nm), "upd.%s", zone);
        o += (size_t)write_uncompressed_name(p, o, 600, nm);
        const uint8_t tail[] = { 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 99 };
        memcpy(p + o, tail, sizeof(tail)); o += sizeof(tail);
    }
    return o;
}

static void test_opcode_tsig_matrix(void) {
    printf("[TEST] Sweep: NOTIFY/UPDATE/UDP-IXFR x zone type x ACL x TSIG...\n");
    sw_teardown();
    g_sw.cfg = sw_conf(CONF_OPS);
    sw_add_zone("example.", ZONE_EXAMPLE);
    char *n3 = make_nsec3_zone(false); sw_add_zone("n3.example.", n3); free(n3);
    sw_add_zone("other.test.", ZONE_OTHER);
    sw_add_zone("geo.test.", ZONE_GEO);
    sw_add_zone("nosoa.test.", ZONE_NOSOA);
    sw_finish_view();
    tsig_key_t *k1 = find_tsig_key_by_name(g_sw.cfg, "k1"), *k2 = find_tsig_key_by_name(g_sw.cfg, "k2");
    tsig_key_t bogus; memset(&bogus, 0, sizeof(bogus)); bogus.name = "nokey."; bogus.algorithm = "hmac-sha256";
    memset(bogus.secret_decoded, 1, 16); bogus.secret_decoded_len = 16;
    tsig_key_t *keys[] = { NULL, k1, k2, &bogus };
    const char *zones[] = { "example.", "n3.example.", "other.test.", "geo.test.", "nosoa.test.", "unknown.test." };
    const char *ips[] = { "192.0.2.100", "10.1.2.3", "127.0.0.1", "127.0.0.2", "203.0.113.5" };
    struct { uint8_t op; uint16_t qt; int serial; bool tc; } kinds[] = {
        { 4, 6, 2026092501, false }, { 4, 6, -1, false }, { 4, 6, 1, true }, { 4, 1, -1, false },
        { 5, 6, -1, false }, { 5, 6, -1, true }, { 5, 1, -1, false },
        { 0, 251, 2026092501, false }, { 0, 251, 1, false }, { 0, 251, -1, false }, { 0, 252, -1, false },
        { 0, 1, -1, false }, { 2, 1, -1, false }, { 6, 1, -1, false },
    };
    uint8_t req[1024];
    for (size_t z = 0; z < NELEM(zones); z++)
    for (size_t k = 0; k < NELEM(kinds); k++)
    for (size_t key = 0; key < NELEM(keys); key++)
    for (size_t ip = 0; ip < NELEM(ips); ip++) {
        if (key && !keys[key]) continue;
        size_t len = op_build(req, kinds[k].op, zones[z], kinds[k].qt, kinds[k].serial, kinds[k].tc);
        if (keys[key]) {
            uint8_t mac[64]; size_t ml = sizeof(mac);
            if (tsig_sign_packet(req, &len, sizeof(req), keys[key], 0, mac, &ml, NULL, 0, false) != 0) continue;
            if ((ip & 1) && key == 1) req[len - 20] ^= 0x5A;          /* damage the MAC */
        }
        sw_run(req, len, 512, zones[z], kinds[k].qt, ips[ip], (ip & 1) != 0);
    }
    /* RRL early-drop: hammer from one client so the bucket is exhausted */
    for (int i = 0; i < 200; i++) {
        size_t len = sw_build(req, (uint16_t)i, 1, 0, (i & 1) ? "nx.other.test." : "www.other.test.", 1, 1, 0);
        sw_run(req, len, 512, (i & 1) ? "nx.other.test." : "www.other.test.", 1, "198.51.100.77", false);
    }
    sw_teardown();
    printf("  -> opcode/TSIG matrix passed.\n");
}

int main(void) {
    wd_start("test_coverage_sweep", 600);
    printf("=== Coverage Sweep Tests ===\n");
    signal(SIGPIPE, SIG_IGN);
    WD_PHASE("test_engine_helper_edges"); test_engine_helper_edges();
    WD_PHASE("test_wire_name_edges"); test_wire_name_edges();
    WD_PHASE("test_wire_rr_sweep"); test_wire_rr_sweep();
    WD_PHASE("test_wire_tsig_sweep"); test_wire_tsig_sweep();
    WD_PHASE("test_wire_edns_sweep"); test_wire_edns_sweep();
    WD_PHASE("test_zone_parser_sweep"); test_zone_parser_sweep();
    WD_PHASE("test_tinydns_sweep"); test_tinydns_sweep();
    WD_PHASE("test_snapshot_catalog_sequence"); test_snapshot_catalog_sequence();
    WD_PHASE("test_ecs_cookie_rrl_dnstap_edges"); test_ecs_cookie_rrl_dnstap_edges();
    WD_PHASE("test_dnstap_edges"); test_dnstap_edges();
    WD_PHASE("test_update_matrix"); test_update_matrix();
    WD_PHASE("test_xfr_roundtrips"); test_xfr_roundtrips();
    WD_PHASE("test_config_sweep"); test_config_sweep();
    WD_PHASE("test_program_zone_emulated"); test_program_zone_emulated();
    WD_PHASE("test_forward_zone_scenarios"); test_forward_zone_scenarios();
    WD_PHASE("test_sweep_query_engine"); test_sweep_query_engine();
    WD_PHASE("test_opcode_tsig_matrix"); test_opcode_tsig_matrix();
    printf("=== All Coverage Sweep Tests PASSED ===\n");
    return 0;
}

/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}

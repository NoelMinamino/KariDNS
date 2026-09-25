/*
 * test_coverage_sweep_net.c - end-to-end coverage sweeps for dag's network paths.
 *
 * An in-process fake authoritative server (UDP, TCP, DNS-over-TLS, DNS-over-HTTPS and
 * plain-HTTP DoH on 127.0.0.1, self-signed certificate generated at start-up) answers
 * according to the first label of the query name ("tc", "big", "badcookie", "tsig",
 * "trace", ...). dag's real main() is then run (in a forked child each time, so exit()
 * and hangs are contained) with a matrix of command lines, followed by --replay runs
 * over generated PCAP / dnstap / text inputs against two differently-behaving servers,
 * and by TSIG / SIG(0) key-file loading with keys generated on the fly.
 * dag.c is compiled into this test with main() renamed (same as test_dag_format).
 */
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

#define main dag_main
#include "../tools/dag.c"
#undef main

#include "dns_zone_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

#define N(a) (sizeof(a) / sizeof((a)[0]))
#define TSIG_SECRET_B64 "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"   /* "secretsecretsecretsecret" */

static char g_tmp[256];
static char g_cert_path[300], g_key_path[300];

/* ======================================================================
 * Fake server
 * ==================================================================== */
typedef struct {
    int udp, tcp, tls, http;
    int port, tls_port, http_port;
    int variant;                 /* 1 = second server for replay diffs */
    SSL_CTX *ctx;
    pthread_t thr;
} fsrv_t;

static volatile int g_stop;
static pthread_mutex_t g_hop_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_hop_count[64];

static tsig_key_t g_srv_key;

static size_t put_name(uint8_t *p, size_t o, size_t cap, const char *n) {
    long w = write_uncompressed_name(p, o, cap, n);
    return w > 0 ? o + (size_t)w : o;
}
static size_t put_rr(uint8_t *p, size_t o, size_t cap, const char *name, uint16_t t, uint32_t ttl, const uint8_t *rd, uint16_t rl) {
    if (o + strlen(name) + 12 + rl > cap) return o;
    o = put_name(p, o, cap, name);
    p[o++] = (uint8_t)(t >> 8); p[o++] = (uint8_t)t; p[o++] = 0; p[o++] = 1;
    p[o++] = (uint8_t)(ttl >> 24); p[o++] = (uint8_t)(ttl >> 16); p[o++] = (uint8_t)(ttl >> 8); p[o++] = (uint8_t)ttl;
    p[o++] = (uint8_t)(rl >> 8); p[o++] = (uint8_t)rl; memcpy(p + o, rd, rl); return o + rl;
}
static size_t soa_rd(uint8_t *rd, uint32_t serial) {
    size_t o = 0;
    o = put_name(rd, o, 256, "ns.test."); o = put_name(rd, o, 256, "h.test.");
    uint32_t v[5] = { serial, 3600, 600, 86400, 60 };
    for (int i = 0; i < 5; i++) { rd[o++] = (uint8_t)(v[i] >> 24); rd[o++] = (uint8_t)(v[i] >> 16); rd[o++] = (uint8_t)(v[i] >> 8); rd[o++] = (uint8_t)v[i]; }
    return o;
}

static int hop_next(const char *qname) {
    uint32_t h = calc_fnv1a_str(qname) & 63;
    pthread_mutex_lock(&g_hop_lock);
    int v = g_hop_count[h]++;
    pthread_mutex_unlock(&g_hop_lock);
    return v;
}

/* Builds the answer. Returns 0 for "no reply". *nmsg > 1 for multi-message (AXFR). */
static size_t fs_answer(const fsrv_t *s, const uint8_t *q, size_t ql, uint8_t *r, size_t cap, int transport, int msgidx, int *nmsg) {
    *nmsg = 1;
    if (ql < 12) return 0;
    char qname[300] = ".";
    size_t qe = 12;
    if (extract_wire_name_to_buffer(q, ql, 12, &qe, qname, sizeof(qname)) != 0) return 0;
    if (qe + 4 > ql) return 0;
    uint16_t qtype = (uint16_t)((q[qe] << 8) | q[qe + 1]);
    uint8_t opcode = (q[2] >> 3) & 0x0F;
    char label[64] = ""; { size_t i = 0; while (qname[i] && qname[i] != '.' && i < 63) { label[i] = (char)tolower((unsigned char)qname[i]); i++; } label[i] = 0; }
    edns_info_t e; memset(&e, 0, sizeof(e));
    uint16_t qd = (uint16_t)((q[4] << 8) | q[5]), an = (uint16_t)((q[6] << 8) | q[7]), ns = (uint16_t)((q[8] << 8) | q[9]), ar = (uint16_t)((q[10] << 8) | q[11]);
    bool edns_ok = parse_edns_opt(q, ql, qd, an, ns, ar, &e) == 0 && e.present;
    bool has_tsig = packet_has_tsig(q, ql);
    uint8_t reqmac[64]; size_t reqmac_len = 0;
    if (has_tsig) (void)tsig_verify_packet(q, ql, &g_srv_key, NULL, 0, NULL, 0, false, reqmac, &reqmac_len);

    if (!strcmp(label, "silent")) return 0;
    if (!strcmp(label, "short")) { memcpy(r, q, 6); r[2] |= 0x80; return 6; }

    memcpy(r, q, qe + 4);
    r[2] = (uint8_t)(0x80 | (opcode << 3) | 0x04 | (q[2] & 0x01));
    r[3] = 0x80;
    r[4] = 0; r[5] = 1; r[6] = r[7] = r[8] = r[9] = r[10] = r[11] = 0;
    if (!strcmp(label, "wrongid")) r[1] ^= 0x01;
    size_t o = qe + 4;
    uint16_t ancount = 0, nscount = 0, arcount = 0;
    uint8_t rd[512]; size_t rl;
    uint8_t ext_rcode = 0;
    uint32_t ttl = s->variant ? 120 : 300;

    if (opcode == 5 || opcode == 4) {                 /* UPDATE / NOTIFY */
        if (!strcmp(label, "refused")) r[3] |= 5;
        goto finish;
    }
    if (opcode != 0) { r[3] |= 4; goto finish; }

    if (!strcmp(label, "qmismatch")) { r[12] ^= 0; if (qe > 13) r[13] ^= 0x20 ^ 0x01; }
    if (!strcmp(label, "nxdomain")) { r[3] |= 3; rl = soa_rd(rd, 1); o = put_rr(r, o, cap, "test.", 6, 60, rd, (uint16_t)rl); nscount++; goto finish; }
    if (!strcmp(label, "servfail")) { r[3] |= 2; goto finish; }
    if (!strcmp(label, "refused")) { r[3] |= 5; goto finish; }
    if (!strcmp(label, "formerr")) { r[3] |= 1; goto finish; }
    if (!strcmp(label, "notimp")) { r[3] |= 4; goto finish; }
    if (!strcmp(label, "badvers") && edns_ok) { ext_rcode = 1; goto finish; }
    if (!strcmp(label, "badcookie") && edns_ok && e.has_cookie && e.server_cookie_len == 0 && transport == 0) { ext_rcode = 1; r[3] |= 7; goto finish; }
    if (!strcmp(label, "tc") && transport == 0) { r[2] |= 0x02; goto finish; }
    if (s->variant && !strcmp(label, "diffrc")) { r[3] |= 3; goto finish; }

    if (qtype == 252 || qtype == 251) {                /* AXFR / IXFR */
        if (!strcmp(label, "axfrrefused")) { r[3] |= 5; goto finish; }
        int total = !strcmp(label, "axfrnoend") ? 2 : 3;
        *nmsg = total;
        if (qtype == 251 && msgidx == 0 && !strcmp(label, "ixfrcur")) { rl = soa_rd(rd, 5); o = put_rr(r, o, cap, qname, 6, 60, rd, (uint16_t)rl); ancount++; *nmsg = 1; goto finish; }
        if (msgidx == 0) { rl = soa_rd(rd, 10); o = put_rr(r, o, cap, qname, 6, 60, rd, (uint16_t)rl); ancount++; }
        for (int i = 0; i < 20; i++) {
            char nm[300]; snprintf(nm, sizeof(nm), "h%d-%d.%s", msgidx, i, qname);
            uint8_t a4[4] = { 192, 0, 2, (uint8_t)i }; o = put_rr(r, o, cap, nm, 1, ttl, a4, 4); ancount++;
        }
        if (msgidx == total - 1 && strcmp(label, "axfrnoend")) { rl = soa_rd(rd, 10); o = put_rr(r, o, cap, qname, 6, 60, rd, (uint16_t)rl); ancount++; }
        goto finish;
    }

    /* +trace / +nssearch style referrals, all pointing back at 127.0.0.1 */
    size_t qlen = strlen(qname);
    bool is_trace = qlen >= 11 && !strcasecmp(qname + qlen - 11, "trace.test.");
    if (!strcmp(qname, ".") && qtype == 2) {
        bool glue = (hop_next(".root") & 1) == 0;
        rl = (size_t)(put_name(rd, 0, 256, "a.root.test.")); o = put_rr(r, o, cap, ".", 2, 518400, rd, (uint16_t)rl); ancount++;
        rl = (size_t)(put_name(rd, 0, 256, "b.root.test.")); o = put_rr(r, o, cap, ".", 2, 518400, rd, (uint16_t)rl); ancount++;
        if (glue) { uint8_t a4[4] = { 127, 0, 0, 1 }; o = put_rr(r, o, cap, "a.root.test.", 1, 518400, a4, 4); arcount++;
                    o = put_rr(r, o, cap, "b.root.test.", 1, 518400, a4, 4); arcount++; }
        goto finish;
    }
    if (!strcmp(qname, "b.root.test.") && qtype == 28) {
        uint8_t a6[16] = { [15] = 1 }; o = put_rr(r, o, cap, qname, 28, 300, a6, 16); ancount++; goto finish;
    }
    if ((!strcmp(qname, "ns.glueless.test.") || !strcmp(qname, "a.root.test.") || !strcmp(qname, "ns1.nss.test.") || !strcmp(qname, "ns2.nss.test.")) && (qtype == 1 || qtype == 28)) {
        if (qtype == 1) { uint8_t a4[4] = { 127, 0, 0, 1 }; o = put_rr(r, o, cap, qname, 1, 300, a4, 4); ancount++; }
        goto finish;
    }
    if (is_trace) {
        int hop = hop_next(qname) % 4;
        if (hop == 0) { r[2] &= (uint8_t)~0x04; rl = put_name(rd, 0, 256, "ns.test."); o = put_rr(r, o, cap, "test.", 2, 3600, rd, (uint16_t)rl); nscount++;
                        uint8_t a4[4] = { 127, 0, 0, 1 }; o = put_rr(r, o, cap, "ns.test.", 1, 3600, a4, 4); arcount++; goto finish; }
        if (hop == 1) { r[2] &= (uint8_t)~0x04; rl = put_name(rd, 0, 256, "ns.glueless.test."); o = put_rr(r, o, cap, "trace.test.", 2, 3600, rd, (uint16_t)rl); nscount++; goto finish; }
        if (hop == 2 && !strcmp(label, "cn")) { rl = put_name(rd, 0, 256, "final.trace.test."); o = put_rr(r, o, cap, qname, 5, 60, rd, (uint16_t)rl); ancount++; goto finish; }
        /* fall through to a normal answer */
    }
    if (!strncmp(qname, "nss.test", 8) || (qlen > 9 && !strcasecmp(qname + qlen - 9, "nss.test."))) {
        if (qtype == 2) {
            rl = put_name(rd, 0, 256, "ns1.nss.test."); o = put_rr(r, o, cap, "nss.test.", 2, 300, rd, (uint16_t)rl); ancount++;
            rl = put_name(rd, 0, 256, "ns2.nss.test."); o = put_rr(r, o, cap, "nss.test.", 2, 300, rd, (uint16_t)rl); ancount++;
            uint8_t a4[4] = { 127, 0, 0, 1 }; o = put_rr(r, o, cap, "ns1.nss.test.", 1, 300, a4, 4); arcount++;
            o = put_rr(r, o, cap, "ns2.nss.test.", 1, 300, a4, 4); arcount++;           /* duplicate address */
            uint8_t a6[16] = { [15] = 1 }; o = put_rr(r, o, cap, "ns1.nss.test.", 28, 300, a6, 16); arcount++;
            goto finish;
        }
        if (qtype == 6) { rl = soa_rd(rd, (uint32_t)(hop_next("soa-serial") + 1)); o = put_rr(r, o, cap, "nss.test.", 6, 300, rd, (uint16_t)rl); ancount++; goto finish; }
    }

    /* ordinary data */
    int reps = !strcmp(label, "big") ? 60 : 1;
    for (int k = 0; k < reps; k++) {
        if (qtype == 1 || qtype == 255) { uint8_t a4[4] = { 192, 0, 2, (uint8_t)(1 + k + s->variant) }; o = put_rr(r, o, cap, qname, 1, ttl, a4, 4); ancount++; }
        if (qtype == 28 || qtype == 255) { uint8_t a6[16] = { 0x00, 0x64, 0xff, 0x9b, [12] = 0xC0, [13] = 0, [14] = 0, [15] = 0xAA }; o = put_rr(r, o, cap, qname, 28, ttl, a6, 16); ancount++; }
        if (qtype == 16 || qtype == 255) { uint8_t t[40]; t[0] = 30; memset(t + 1, 'a' + (k % 26), 30); o = put_rr(r, o, cap, qname, 16, ttl, t, 31); ancount++; }
        if (qtype == 15 || qtype == 255) { rd[0] = 0; rd[1] = 10; rl = put_name(rd, 2, 256, "mail.test."); o = put_rr(r, o, cap, qname, 15, ttl, rd, (uint16_t)rl); ancount++; }
        if (qtype == 6) { rl = soa_rd(rd, 7); o = put_rr(r, o, cap, qname, 6, ttl, rd, (uint16_t)rl); ancount++; }
        if (qtype == 2) { rl = put_name(rd, 0, 256, "ns.test."); o = put_rr(r, o, cap, qname, 2, ttl, rd, (uint16_t)rl); ancount++; }
        if (qtype == 48 || qtype == 255) { uint8_t k2[36] = { 1, 1, 3, 13 }; memset(k2 + 4, 0x42, 32); o = put_rr(r, o, cap, qname, 48, ttl, k2, 36); ancount++; }
        if (qtype == 46 || (qtype == 1 && e.dnssec_ok)) {
            uint8_t sg[64] = { 0, 1, 13, 2, 0, 0, 1, 44, 0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x12, 0x34 };
            size_t sl = put_name(sg, 18, 64, "test."); memset(sg + sl, 0x55, 16); sl += 16;
            o = put_rr(r, o, cap, qname, 46, ttl, sg, (uint16_t)sl); ancount++;
        }
    }
    if (ancount == 0) { rl = soa_rd(rd, 7); o = put_rr(r, o, cap, "test.", 6, 60, rd, (uint16_t)rl); nscount++; }
    if (!strcmp(label, "big") && transport == 0 && o > (edns_ok ? (size_t)(e.udp_payload_size > 512 ? e.udp_payload_size : 512) : 512)) {
        o = qe + 4; ancount = nscount = 0; r[2] |= 0x02;
    }
    if (s->variant && !strcmp(label, "diffextra")) { uint8_t a4[4] = { 198, 51, 100, 1 }; o = put_rr(r, o, cap, "extra.test.", 1, 60, a4, 4); arcount++; }

finish:
    r[6] = (uint8_t)(ancount >> 8); r[7] = (uint8_t)ancount; r[8] = (uint8_t)(nscount >> 8); r[9] = (uint8_t)nscount;
    if (edns_ok && strcmp(label, "noedns")) {
        o = put_name(r, o, cap, ".");
        r[o++] = 0; r[o++] = 41; r[o++] = 0x04; r[o++] = 0xD0;
        r[o++] = ext_rcode; r[o++] = 0; r[o++] = (uint8_t)(e.dnssec_ok ? 0x80 : 0); r[o++] = 0;
        size_t rdl_pos = o; o += 2;
        if (e.has_cookie) {
            bool bad = !strcmp(label, "cookiebad");
            r[o++] = 0; r[o++] = 10; r[o++] = 0; r[o++] = 24;
            memcpy(r + o, e.client_cookie, 8); if (bad) r[o] ^= 0xFF; o += 8;
            for (int i = 0; i < 16; i++) r[o++] = (uint8_t)(0x10 + i);
        }
        if (e.has_nsid_query) { r[o++] = 0; r[o++] = 3; r[o++] = 0; r[o++] = 6; memcpy(r + o, "fake\x01n", 6); o += 6; }
        if (!strcmp(label, "ede") || ext_rcode) { const char *t = "blocked by policy"; r[o++] = 0; r[o++] = 15; r[o++] = 0; r[o++] = (uint8_t)(2 + strlen(t)); r[o++] = 0; r[o++] = 15; memcpy(r + o, t, strlen(t)); o += strlen(t);
                                                  r[o++] = 0; r[o++] = 15; r[o++] = 0; r[o++] = 2; r[o++] = 0x12; r[o++] = 0x34; }
        if (e.has_keepalive_query || transport != 0) { r[o++] = 0; r[o++] = 11; r[o++] = 0; r[o++] = 2; r[o++] = 0; r[o++] = 50; }
        if (e.has_ecs) { r[o++] = 0; r[o++] = 8; r[o++] = 0; r[o++] = 7; r[o++] = 0; r[o++] = 1; r[o++] = 24; r[o++] = 24; r[o++] = 192; r[o++] = 0; r[o++] = 2; }
        if (e.has_mqtype_query) { r[o++] = 0; r[o++] = 21; r[o++] = 0; r[o++] = 2; r[o++] = 0; r[o++] = 28; }
        if (!strcmp(label, "expire")) { r[o++] = 0; r[o++] = 9; r[o++] = 0; r[o++] = 4; r[o++] = 0; r[o++] = 1; r[o++] = 0; r[o++] = 0; }
        if (!strcmp(label, "padopt")) { r[o++] = 0; r[o++] = 12; r[o++] = 0; r[o++] = 4; memset(r + o, 0, 4); o += 4;
                                         r[o++] = 0xAB; r[o++] = 0xCD; r[o++] = 0; r[o++] = 1; r[o++] = 7; }
        uint16_t rdl = (uint16_t)(o - rdl_pos - 2); r[rdl_pos] = (uint8_t)(rdl >> 8); r[rdl_pos + 1] = (uint8_t)rdl;
        arcount++;
    }
    r[10] = (uint8_t)(arcount >> 8); r[11] = (uint8_t)arcount;
    if (has_tsig && strcmp(label, "unsigned")) {
        bool sign = !(*nmsg > 1 && msgidx > 0 && msgidx < *nmsg - 1 && strcmp(label, "tsigall"));
        if (sign) {
            tsig_key_t k = g_srv_key;
            if (!strcmp(label, "badtsig")) { k.secret_decoded[0] ^= 1; }
            uint8_t mac[64]; size_t ml = sizeof(mac);
            memcpy(mac, reqmac, reqmac_len); ml = reqmac_len;
            (void)tsig_sign_packet(r, &o, cap, &k, !strcmp(label, "tsigerr") ? 16 : 0, mac, &ml, NULL, 0, msgidx > 0);
        }
    }
    return o;
}

static void *conn_thread(void *arg);
typedef struct { fsrv_t *s; int fd; SSL *ssl; int kind; } conn_t;   /* kind: 1 tcp, 2 tls */

static ssize_t c_read(conn_t *c, uint8_t *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t k = c->ssl ? SSL_read(c->ssl, b + got, (int)(n - got)) : recv(c->fd, b + got, n - got, 0);
        if (k <= 0) return -1;
        got += (size_t)k;
    }
    return (ssize_t)got;
}
static void c_write(conn_t *c, const uint8_t *b, size_t n) {
    if (c->ssl) (void)SSL_write(c->ssl, b, (int)n); else (void)send(c->fd, b, n, MSG_NOSIGNAL);
}

static const char B64U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static size_t b64url_decode(const char *s, uint8_t *out, size_t cap) {
    uint32_t acc = 0; int bits = 0; size_t o = 0;
    for (; *s && *s != '&' && *s != ' '; s++) {
        const char *p = strchr(B64U, *s); if (!p) { if (*s == '=') break; continue; }
        acc = (acc << 6) | (uint32_t)(p - B64U); bits += 6;
        if (bits >= 8) { bits -= 8; if (o < cap) out[o++] = (uint8_t)(acc >> bits); }
    }
    return o;
}

static void serve_http(conn_t *c, const uint8_t *first, size_t firstlen) {
    char req[8192]; size_t rl = 0;
    memcpy(req, first, firstlen); rl = firstlen;
    while (rl < sizeof(req) - 1) {
        req[rl] = 0;
        if (strstr(req, "\r\n\r\n")) break;
        ssize_t k = c->ssl ? SSL_read(c->ssl, req + rl, (int)(sizeof(req) - 1 - rl)) : recv(c->fd, req + rl, sizeof(req) - 1 - rl, 0);
        if (k <= 0) return;
        rl += (size_t)k;
    }
    req[rl] = 0;
    char *hend = strstr(req, "\r\n\r\n"); if (!hend) return;
    size_t hlen = (size_t)(hend + 4 - req);
    uint8_t q[4096]; size_t ql = 0;
    if (!strncmp(req, "POST", 4)) {
        char *cl = strcasestr(req, "Content-Length:"); size_t blen = cl ? (size_t)atoi(cl + 15) : 0;
        if (blen > sizeof(q)) return;
        size_t have = rl - hlen; memcpy(q, req + hlen, have < blen ? have : blen); ql = have < blen ? have : blen;
        while (ql < blen) { ssize_t k = c_read(c, q + ql, blen - ql); if (k <= 0) return; ql += (size_t)k; }
    } else {
        char *d = strstr(req, "dns="); if (!d) return;
        ql = b64url_decode(d + 4, q, sizeof(q));
    }
    uint8_t r[65535]; int nm;
    size_t n = fs_answer(c->s, q, ql, r, sizeof(r), 3, 0, &nm);
    char h[512]; int hl;
    char label[32] = ""; if (ql > 13) { size_t L = q[12] < 31 ? q[12] : 31; memcpy(label, q + 13, L); label[L] = 0; }
    if (!strcmp(label, "http404")) { hl = snprintf(h, sizeof(h), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"); c_write(c, (uint8_t *)h, (size_t)hl); return; }
    if (!strcmp(label, "chunked")) {
        hl = snprintf(h, sizeof(h), "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n");
        c_write(c, (uint8_t *)h, (size_t)hl);
        size_t half = n / 2;
        hl = snprintf(h, sizeof(h), "%zx\r\n", half); c_write(c, (uint8_t *)h, (size_t)hl); c_write(c, r, half); c_write(c, (const uint8_t *)"\r\n", 2);
        hl = snprintf(h, sizeof(h), "%zx\r\n", n - half); c_write(c, (uint8_t *)h, (size_t)hl); c_write(c, r + half, n - half); c_write(c, (const uint8_t *)"\r\n0\r\n\r\n", 7);
        return;
    }
    hl = snprintf(h, sizeof(h), "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n",
                  !strcmp(label, "badct") ? "text/html" : "application/dns-message", n);
    c_write(c, (uint8_t *)h, (size_t)hl);
    c_write(c, r, n);
}

static void *conn_thread(void *arg) {
    conn_t *c = arg;
    struct timeval tv = { 3, 0 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (c->kind == 2) {
        c->ssl = SSL_new(c->s->ctx);
        SSL_set_fd(c->ssl, c->fd);
        if (SSL_accept(c->ssl) <= 0) goto out;
    }
    for (;;) {
        uint8_t lp[4];
        ssize_t k = c->ssl ? SSL_read(c->ssl, lp, 2) : recv(c->fd, lp, 2, MSG_WAITALL);
        if (k == 1 && !c->ssl) { if (recv(c->fd, lp + 1, 1, 0) != 1) break; k = 2; }
        if (k == 1 && c->ssl) { if (SSL_read(c->ssl, lp + 1, 1) != 1) break; k = 2; }
        if (k != 2) break;
        if ((lp[0] == 'G' && lp[1] == 'E') || (lp[0] == 'P' && lp[1] == 'O')) { serve_http(c, lp, 2); break; }
        size_t ql = ((size_t)lp[0] << 8) | lp[1];
        uint8_t q[65535];
        if (ql == 0 || c_read(c, q, ql) < 0) break;
        int nm = 1;
        for (int m = 0; m < nm; m++) {
            uint8_t r[65535];
            size_t n = fs_answer(c->s, q, ql, r, sizeof(r), c->kind, m, &nm);
            if (!n) break;
            uint8_t hl[2] = { (uint8_t)(n >> 8), (uint8_t)n };
            c_write(c, hl, 2); c_write(c, r, n);
        }
        /* "closeafter": drop the connection after answering, so a client that keeps
         * the connection open (+keepopen) finds it closed on the next query. */
        if (ql > 23 && q[12] == 10 && !memcmp(q + 13, "closeafter", 10)) break;
    }
out:
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    close(c->fd);
    free(c);
    return NULL;
}

static void *srv_thread(void *arg) {
    fsrv_t *s = arg;
    while (!g_stop) {
        struct pollfd p[4] = { { s->udp, POLLIN, 0 }, { s->tcp, POLLIN, 0 }, { s->tls, POLLIN, 0 }, { s->http, POLLIN, 0 } };
        if (poll(p, 4, 100) <= 0) continue;
        if (p[0].revents & POLLIN) {
            uint8_t q[4096], r[65535]; struct sockaddr_storage from; socklen_t fl = sizeof(from);
            ssize_t n = recvfrom(s->udp, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
            if (n > 0) {
                int nm; size_t rl = fs_answer(s, q, (size_t)n, r, sizeof(r), 0, 0, &nm);
                if (rl) {
                    if (rl > 1232) rl = 1232;
                    if (q[12] == 7 && !memcmp(q + 13, "wrongid", 7)) { sendto(s->udp, r, rl, 0, (struct sockaddr *)&from, fl); r[1] ^= 1; }
                    sendto(s->udp, r, rl, 0, (struct sockaddr *)&from, fl);
                }
            }
        }
        for (int i = 1; i < 4; i++) {
            if (!(p[i].revents & POLLIN)) continue;
            int fd = accept(p[i].fd, NULL, NULL);
            if (fd < 0) continue;
            conn_t *c = calloc(1, sizeof(*c)); c->s = s; c->fd = fd; c->kind = (i == 2) ? 2 : 1;
            pthread_t t; pthread_create(&t, NULL, conn_thread, c); pthread_detach(t);
        }
    }
    return NULL;
}

static int bind_any(int type, int port, int *out_port) {
    int fd = socket(AF_INET, type, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    socklen_t al = sizeof(a); getsockname(fd, (struct sockaddr *)&a, &al);
    if (out_port) *out_port = ntohs(a.sin_port);
    if (type == SOCK_STREAM) listen(fd, 64);
    return fd;
}

static void make_cert(void) {
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, pk);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, nm);
    X509_sign(x, pk, EVP_sha256());
    snprintf(g_cert_path, sizeof(g_cert_path), "%s/cert.pem", g_tmp);
    snprintf(g_key_path, sizeof(g_key_path), "%s/key.pem", g_tmp);
    FILE *f = fopen(g_cert_path, "w"); PEM_write_X509(f, x); fclose(f);
    f = fopen(g_key_path, "w"); PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL); fclose(f);
    X509_free(x); EVP_PKEY_free(pk);
}

static void fs_start(fsrv_t *s, int variant) {
    memset(s, 0, sizeof(*s));
    s->variant = variant;
    for (int tries = 0; tries < 50; tries++) {
        s->tcp = bind_any(SOCK_STREAM, 0, &s->port);
        s->udp = bind_any(SOCK_DGRAM, s->port, NULL);
        if (s->udp >= 0) break;
        close(s->tcp);
    }
    assert(s->udp >= 0);
    s->tls = bind_any(SOCK_STREAM, 0, &s->tls_port);
    s->http = bind_any(SOCK_STREAM, 0, &s->http_port);
    s->ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(s->ctx, g_cert_path, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(s->ctx, g_key_path, SSL_FILETYPE_PEM);
    pthread_create(&s->thr, NULL, srv_thread, s);
}

/* ======================================================================
 * Running dag's main() in a child process
 * ==================================================================== */
static int g_runs, g_nonzero;
static int run_dag(int argc, char **argv) {
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        const char *v = getenv("SWNET_VERBOSE");   /* debugging aid: show output of runs containing this token */
        bool show = false;
        if (v) for (int i = 0; i < argc; i++) if (strstr(argv[i], v)) show = true;
        if (!show) { int dn = open("/dev/null", O_WRONLY); dup2(dn, 1); dup2(dn, 2); }
        alarm(20);
        int rc = dag_main(argc, argv);
        fflush(stdout);
        exit(rc & 0xFF);
    }
    int st = 0; waitpid(pid, &st, 0);
    g_runs++;
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    if (rc) g_nonzero++;
    if (WIFSIGNALED(st) && WTERMSIG(st) != SIGALRM) {
        fprintf(stderr, "  !! dag crashed with signal %d:", WTERMSIG(st));
        for (int i = 0; i < argc; i++) fprintf(stderr, " %s", argv[i]);
        fprintf(stderr, "\n");
        assert(!"dag crashed");
    }
    return rc;
}

#define MAXA 48
static int run_line(const char *fmt, ...) {
    char line[4096]; va_list ap; va_start(ap, fmt); vsnprintf(line, sizeof(line), fmt, ap); va_end(ap);
    static char buf[4096]; char *argv[MAXA]; int argc = 0;
    memcpy(buf, line, sizeof(buf));
    char *save = NULL;
    argv[argc++] = "dag";
    for (char *t = strtok_r(buf, " ", &save); t && argc < MAXA - 1; t = strtok_r(NULL, " ", &save)) {
        for (char *u = t; *u; u++) if (*u == '~') *u = ' ';     /* '~' encodes a space inside one argument */
        argv[argc++] = t;
    }
    argv[argc] = NULL;
    return run_dag(argc, argv);
}

/* ======================================================================
 * Key material: TSIG key file, BIND SIG(0) private keys (RSA/ECDSA/Ed25519), PEM
 * ==================================================================== */
static void b64(const uint8_t *in, size_t n, char *out) { EVP_EncodeBlock((unsigned char *)out, in, (int)n); }
static void bn_field(FILE *f, const char *label, EVP_PKEY *pk, const char *param, int pad) {
    BIGNUM *bn = NULL; if (EVP_PKEY_get_bn_param(pk, param, &bn) != 1) return;
    uint8_t buf[1024]; int n = pad ? BN_bn2binpad(bn, buf, pad) : BN_bn2bin(bn, buf);
    char o[2048]; b64(buf, (size_t)n, o); fprintf(f, "%s: %s\n", label, o); BN_free(bn);
}
static char g_k_rsa[400], g_k_ec[400], g_k_ec384[400], g_k_ed[400], g_k_bad[400], g_k_alg[400], g_tsigfile[400], g_pem[400];
static void make_keys(void) {
    snprintf(g_tsigfile, sizeof(g_tsigfile), "%s/tsig.key", g_tmp);
    FILE *f = fopen(g_tsigfile, "w");
    fprintf(f, "key \"tsig-key.\" {\n\talgorithm hmac-sha256;\n\tsecret \"%s\";\n};\n", TSIG_SECRET_B64); fclose(f);
    EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)1024);
    snprintf(g_k_rsa, sizeof(g_k_rsa), "%s/Kupd.test.+008+11111.private", g_tmp);
    f = fopen(g_k_rsa, "w");
    fprintf(f, "Private-key-format: v1.3\nAlgorithm: 8 (RSASHA256)\n");
    bn_field(f, "Modulus", rsa, OSSL_PKEY_PARAM_RSA_N, 0); bn_field(f, "PublicExponent", rsa, OSSL_PKEY_PARAM_RSA_E, 0);
    bn_field(f, "PrivateExponent", rsa, OSSL_PKEY_PARAM_RSA_D, 0); bn_field(f, "Prime1", rsa, OSSL_PKEY_PARAM_RSA_FACTOR1, 0);
    bn_field(f, "Prime2", rsa, OSSL_PKEY_PARAM_RSA_FACTOR2, 0); bn_field(f, "Exponent1", rsa, OSSL_PKEY_PARAM_RSA_EXPONENT1, 0);
    bn_field(f, "Exponent2", rsa, OSSL_PKEY_PARAM_RSA_EXPONENT2, 0); bn_field(f, "Coefficient", rsa, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, 0);
    fclose(f);
    snprintf(g_pem, sizeof(g_pem), "%s/sig0.pem", g_tmp);
    f = fopen(g_pem, "w"); PEM_write_PrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL); fclose(f);
    EVP_PKEY_free(rsa);
    const char *curves[2] = { "P-256", "P-384" }; char *paths[2] = { g_k_ec, g_k_ec384 };
    for (int i = 0; i < 2; i++) {
        EVP_PKEY *ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curves[i]);
        snprintf(paths[i], 400, "%s/Kupd.test.+%03d+2222%d.private", g_tmp, 13 + i, i);
        f = fopen(paths[i], "w"); fprintf(f, "Private-key-format: v1.3\nAlgorithm: %d\n", 13 + i);
        bn_field(f, "PrivateKey", ec, OSSL_PKEY_PARAM_PRIV_KEY, i ? 48 : 32); fclose(f);
        char kp[420]; snprintf(kp, sizeof(kp), "%.*s.key", (int)(strlen(paths[i]) - 8), paths[i]);
        f = fopen(kp, "w"); fprintf(f, "; comment\nupd.test. IN KEY 512 3 %d AAAA\n", 13 + i); fclose(f);
        EVP_PKEY_free(ec);
    }
    EVP_PKEY *ed = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    uint8_t raw[32]; size_t rl = sizeof(raw); EVP_PKEY_get_raw_private_key(ed, raw, &rl);
    snprintf(g_k_ed, sizeof(g_k_ed), "%s/Kupd.test.+015+33333.private", g_tmp);
    char o[128]; b64(raw, 32, o);
    f = fopen(g_k_ed, "w"); fprintf(f, "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\nPrivateKey: %s\n", o); fclose(f);
    EVP_PKEY_free(ed);
    snprintf(g_k_bad, sizeof(g_k_bad), "%s/Kupd.test.+013+44444.private", g_tmp);
    f = fopen(g_k_bad, "w"); fprintf(f, "Private-key-format: v1.3\nAlgorithm: 13\nPrivateKey: AAAA\n"); fclose(f);
    snprintf(g_k_alg, sizeof(g_k_alg), "%s/nameless.private", g_tmp);
    f = fopen(g_k_alg, "w"); fprintf(f, "Private-key-format: v1.3\nAlgorithm: 5\n"); fclose(f);
}

static void test_key_files(void) {
    printf("[TEST] net sweep: TSIG key file / SIG(0) key loaders...\n");
    const char *files[] = { g_k_rsa, g_k_ec, g_k_ec384, g_k_ed, g_k_bad, g_k_alg, g_tsigfile, g_pem, "/nonexistent" };
    for (size_t i = 0; i < N(files); i++) {
        sig0_key_t k; memset(&k, 0, sizeof(k));
        if (load_bind_sig0_private_key(files[i], &k)) { if (k.pkey) EVP_PKEY_free(k.pkey); free(k.signer_name); }
        memset(&k, 0, sizeof(k));
        if (load_sig0_pkey(files[i], &k)) { if (k.pkey) EVP_PKEY_free(k.pkey); free(k.signer_name); }
        query_opts_t qo; memset(&qo, 0, sizeof(qo));
        parse_tsig_keyfile(files[i], &qo);
        free_query_opts(&qo);
    }
    const char *tsig_strs[] = { "hmac-sha256:tsig-key.:" TSIG_SECRET_B64, "tsig-key.:" TSIG_SECRET_B64, "hmac-md5:k:c2Vj",
                                "hmac-sha512:k", "::", "", "bogus-alg:k:c2Vj", "k:@@@@" };
    for (size_t i = 0; i < N(tsig_strs); i++) {
        query_opts_t qo; memset(&qo, 0, sizeof(qo));
        char *s = strdup(tsig_strs[i]); parse_tsig_str(s, &qo); free(s); free_query_opts(&qo);
    }
    /* key files with odd layouts */
    char p[400]; snprintf(p, sizeof(p), "%s/odd.key", g_tmp);
    const char *odd[] = { "key tsig { algorithm hmac-sha1; secret \"c2VjcmV0\"; };\n", "key \"x\" {\n};\n", "garbage\n", "",
                          "key \"y\" { secret \"c2VjcmV0\"; algorithm \"hmac-sha384\"; };" };
    for (size_t i = 0; i < N(odd); i++) {
        FILE *f = fopen(p, "w"); fputs(odd[i], f); fclose(f);
        query_opts_t qo; memset(&qo, 0, sizeof(qo)); parse_tsig_keyfile(p, &qo); free_query_opts(&qo);
        sig0_key_t k; memset(&k, 0, sizeof(k)); (void)load_bind_sig0_private_key(p, &k);
    }
    /* BIND private-key files: continuation lines, bad scalars, partial RSA, names from a companion .key */
    struct { const char *file, *body, *keyfile; } bind[] = {
        { "Kcont.test+013+00001.private", "Private-key-format: v1.3\nAlgorithm: 13\nPrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n", NULL },
        { "Kzero.test+013+00002.private", "Private-key-format: v1.3\nAlgorithm: 13\nPrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", NULL },
        { "Kbig.test+013+00003.private", "Private-key-format: v1.3\nAlgorithm: 13\nPrivateKey: //////////////////////////////////////////8=\n", NULL },
        { "Kbig.test+014+00004.private", "Private-key-format: v1.3\nAlgorithm: 14\nPrivateKey: ////////////////////////////////////////////////////////////////\n", NULL },
        { "Krsa.test+008+00005.private", "Private-key-format: v1.3\nAlgorithm: 8\nModulus: AQAB\n", NULL },
        { "Krsa.test+008+00006.private", "Private-key-format: v1.3\nAlgorithm: 8\nModulus: 0Zb3\nPublicExponent: AQAB\nPrivateExponent: AQAB\n", NULL },
        { "Krsa.test+008+00007.private", "Private-key-format: v1.3\nAlgorithm: 8\nModulus: 0Zb3\nPublicExponent: AQAB\nPrivateExponent: AQAB\nPrime1: Aw==\n", NULL },
        { "Krsa.test+008+00008.private", "Private-key-format: v1.3\nAlgorithm: 8\nModulus: 0Zb3\nPublicExponent: AQAB\nPrivateExponent: AQAB\nPrime1: Aw==\nPrime2: BQ==\nExponent1: AQ==\n", NULL },
        { "Ked.test+015+00009.private", "Private-key-format: v1.3\nAlgorithm: 15\nPrivateKey: AAAA\n", NULL },
        { "noname_ec.private", NULL, "; comment\n\n   \t\nupd.test IN KEY 512 3 13 AAAA\n" },
        { "noname_ec2.private", NULL, "#only comments\nnoterminator" },
        { "noname_ec3.private", NULL, NULL },
        { "Kx.private", "Private-key-format: v1.3\n", NULL },
        { "Kempty.private", "", NULL },
    };
    for (size_t i = 0; i < N(bind); i++) {
        char fp[400], kp[400];
        snprintf(fp, sizeof(fp), "%s/%s", g_tmp, bind[i].file);
        FILE *f = fopen(fp, "w");
        if (bind[i].body) fputs(bind[i].body, f);
        else { FILE *src = fopen(g_k_ec, "r"); char b[4096]; size_t n = fread(b, 1, sizeof(b), src); fclose(src); fwrite(b, 1, n, f); }
        fclose(f);
        if (bind[i].keyfile) {
            snprintf(kp, sizeof(kp), "%.*s.key", (int)(strlen(fp) - 8), fp);
            f = fopen(kp, "w"); fputs(bind[i].keyfile, f); fclose(f);
        }
        for (int variant = 0; variant < 3; variant++) {
            sig0_key_t k; memset(&k, 0, sizeof(k));
            if (variant == 1) k.algorithm = 13;                       /* algorithm forced by +sig0-alg */
            if (variant == 2) k.signer_name = strdup("signer.test.");
            if (load_bind_sig0_private_key(fp, &k)) { if (k.pkey) EVP_PKEY_free(k.pkey); }
            free(k.signer_name);
        }
    }
    /* PEM keys of every family (P-521 falls back to P-256, X25519 is unsupported), and a preloaded key */
    struct { const char *alg; const char *param; } pem[] = { { "EC", "P-384" }, { "EC", "P-521" }, { "ED25519", NULL }, { "X25519", NULL }, { "RSA", NULL } };
    for (size_t i = 0; i < N(pem); i++) {
        EVP_PKEY *pk = !strcmp(pem[i].alg, "EC") ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", pem[i].param)
                     : !strcmp(pem[i].alg, "RSA") ? EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)1024)
                     : EVP_PKEY_Q_keygen(NULL, NULL, pem[i].alg);
        if (!pk) continue;
        char fp[400]; snprintf(fp, sizeof(fp), "%s/k%zu.pem", g_tmp, i);
        FILE *f = fopen(fp, "w"); PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL); fclose(f);
        sig0_key_t k; memset(&k, 0, sizeof(k));
        k.pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        if (load_sig0_pkey(fp, &k)) {}
        if (k.pkey) EVP_PKEY_free(k.pkey);
        memset(&k, 0, sizeof(k)); k.pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        if (load_bind_sig0_private_key(g_k_ed, &k)) {}
        if (k.pkey) EVP_PKEY_free(k.pkey);
        EVP_PKEY_free(pk);
    }
    /* TSIG key files: unquoted secret, no algorithm, oversized file */
    const char *more[] = { "key k { secret c2VjcmV0; };\n", "key k {\n\tsecret\tc2VjcmV0\n}", "key \"n\" { algorithm hmac-sha1 };\n" };
    for (size_t i = 0; i < N(more); i++) {
        FILE *f = fopen(p, "w"); fputs(more[i], f); fclose(f);
        query_opts_t qo; memset(&qo, 0, sizeof(qo)); parse_tsig_keyfile(p, &qo); free_query_opts(&qo);
    }
    { FILE *f = fopen(p, "w"); for (int i = 0; i < 70 * 1024; i++) fputc(' ', f); fclose(f);
      query_opts_t qo; memset(&qo, 0, sizeof(qo)); parse_tsig_keyfile(p, &qo); free_query_opts(&qo); }
    printf("  -> key loaders done.\n");
}

/* ======================================================================
 * dag command-line matrix against the fake server
 * ==================================================================== */
static void test_dag_cli_matrix(fsrv_t *s, fsrv_t *s2) {
    printf("[TEST] net sweep: dag CLI matrix against the fake server...\n");
    char srv[64]; snprintf(srv, sizeof(srv), "@127.0.0.1 -p %d +time=1 +tries=1", s->port);
    const char *labels[] = { "ok", "tc", "big", "nxdomain", "servfail", "refused", "formerr", "notimp", "badvers", "badcookie",
                             "cookiebad", "noedns", "ede", "expire", "padopt", "qmismatch", "short", "tsig", "unsigned", "badtsig", "tsigerr" };
    const char *opts[] = {
        "", "+tcp", "+short", "+yaml", "+multi +dnssec", "+cookie", "+nsid +expire +padding=64 +subnet=192.0.2.0/24 +ednsopt=65001:abcd",
        "+noedns", "+edns=1 +ednsflags=0x80", "+besteffort", "+ignore", "+qr", "+identify +short", "+dns64prefix", "+ttlunits +rrcomments +nottlid",
        "+ldnsz", "+hexdump", "+nobadcookie", "+cookie=0102030405060708", "+showbadcookie +showbadvers", "+noall +answer +stats",
        "+nocomments +noquestion +noauthority +noadditional", "+onesoa +nocrypto +noclass", "+unknownformat +expandaaaa +split=8",
        "+yaml +dnssec +nsid +cookie", "+mqtype=AAAA,TXT", "+keepalive +tcp", "+keepopen +tcp", "+vc +qr +multiline",
        "-4", "-u", "+tcp +ednsopt=12:0000", "+norec +adflag +cdflag +aaflag +tcflag +zflag", "+opcode=5", "+coflag",
    };
    const char *types[] = { "A", "AAAA", "TXT", "ANY", "MX", "SOA", "NS", "DNSKEY", "RRSIG", "TYPE65534" };
    for (size_t l = 0; l < N(labels); l++) {
        for (size_t o = 0; o < N(opts); o++) {
            if (l > 3 && o % 3 != l % 3) continue;          /* keep the matrix size reasonable */
            const char *t = types[(l + o) % N(types)];
            const char *keyopt = (!strncmp(labels[l], "tsig", 4) || !strcmp(labels[l], "unsigned") || !strcmp(labels[l], "badtsig"))
                                 ? "-y~hmac-sha256:tsig-key.:" TSIG_SECRET_B64 : "";
            char kbuf[200]; snprintf(kbuf, sizeof(kbuf), "%s", keyopt);
            for (char *u = kbuf; *u; u++) if (*u == '~') *u = ' ';
            run_line("%s %s %s %s.test. %s", srv, opts[o], kbuf, labels[l], t);
        }
    }
    /* multi-query command lines, classes, reverse, batch files */
    run_line("%s ok.test. A ok.test. AAAA +tcp big.test. TXT -c CH ok.test.", srv);
    run_line("%s -x 192.0.2.1 -x 2001:db8::1", srv);
    run_line("%s -t ANY -q q1.test. -q q2.test. +short", srv);
    run_line("%s -c ANY ok.test. -c HS ok.test. -c CLASS42 ok.test.", srv);
    char batch[400]; snprintf(batch, sizeof(batch), "%s/batch.txt", g_tmp);
    FILE *f = fopen(batch, "w"); fprintf(f, "ok.test. A\nbig.test. TXT +tcp\n# comment\n\nnxdomain.test.\n-x 192.0.2.5\n+yaml ok.test. MX\n"); fclose(f);
    run_line("%s -f %s", srv, batch);
    run_line("%s -f /nonexistent/batch", srv);
    /* zone transfers (plain and TSIG) */
    const char *xfr[] = { "axfr", "axfrrefused", "axfrnoend", "tsigall", "ixfrcur" };
    for (size_t i = 0; i < N(xfr); i++) {
        run_line("%s %s.test. AXFR", srv, xfr[i]);
        run_line("%s %s.test. AXFR +yaml", srv, xfr[i]);
        run_line("%s -y hmac-sha256:tsig-key.:%s %s.test. AXFR +multi", srv, TSIG_SECRET_B64, xfr[i]);
        run_line("%s %s.test. -t IXFR=5 +tcp", srv, xfr[i]);
        run_line("%s -y hmac-sha256:tsig-key.:%s %s.test. -t IXFR=3", srv, TSIG_SECRET_B64, xfr[i]);
    }
    run_line("%s -y hmac-sha256:tsig-key.:Ymxh tsig.test. AXFR", srv);
    run_line("%s -k %s tsig.test. A", srv, g_tsigfile);
    /* dynamic UPDATE with TSIG / SIG(0) */
    const char *keys[] = { g_k_rsa, g_k_ec, g_k_ec384, g_k_ed, g_k_bad };
    for (size_t k = 0; k < N(keys); k++)
        run_line("%s -k %s upd.test. SOA --update-add upd.test.~300~A~192.0.2.9 --update-del old.upd.test.~A", srv, keys[k]);
    run_line("%s +sig0-pkey=%s +sig0-name=upd.test. +sig0-alg=8 +sig0-keytag=1234 upd.test. SOA --update-add a.upd.test.~60~TXT~\"x~y\"", srv, g_pem);
    run_line("%s upd.test. SOA --prereq-nxdomain n.upd.test. --prereq-yxdomain y.upd.test. --prereq-nxrrset~n.upd.test.~A --prereq-yxrrset z.upd.test. A 192.0.2.1 --update-add z.upd.test.~IN~A~192.0.2.2 --update-del-exact z.upd.test.~A~192.0.2.1", srv);
    run_line("%s refused.test. SOA --update-add r.test.~60~BOGUS~x --update-add bad --update-del ~", srv);
    run_line("%s upd.test. SOA --prereq=nxrrset:a.upd.test.:AAAA --prereq=yxdomain:b.upd.test. --prereq=nxdomain --prereq=yxrrset:c.upd.test.:TXT:\"q\"", srv);
    /* trace and nssearch */
    run_line("%s +trace www.trace.test. A", srv);
    run_line("%s +trace cn.trace.test. A +tcp", srv);
    run_line("%s +trace +dnssec +multi deep.x.trace.test. AAAA", srv);
    run_line("%s +trace +short www.trace.test.", srv);
    run_line("%s +trace +yaml www.trace.test.", srv);
    run_line("%s +nssearch nss.test.", srv);
    run_line("%s +nssearch +tcp nss.test.", srv);
    run_line("%s +nssearch refused.test.", srv);
    /* server list syntax, bad ports, IPv6 */
    run_line("@127.0.0.1:%d,127.0.0.1:%d,[::1]:1,[::1,,bad:port:x +time=1 +tries=1 ok.test.", s->port, s2->port);
    run_line("@127.0.0.1:%d,127.0.0.1:%d +allcompare +time=1 +tries=1 diffextra.test.", s->port, s2->port);
    run_line("@127.0.0.1#%d +time=1 +tries=1 ok.test.", s->port);
    run_line("@localhost -p %d -6 +time=1 +tries=1 ok.test.", s->port);
    run_line("@127.0.0.1 -p %d -b 127.0.0.1#0 +time=1 +tries=1 ok.test.", s->port);
    run_line("-p %d +time=1 +tries=1 ok.test.", s->port);
    /* silent server: timeouts and retries (one each, they cost a second) */
    run_line("%s silent.test.", srv);
    run_line("@127.0.0.1 -p %d +time=1 +tries=2 +retry=1 wrongid.test.", s->port);
    run_line("%s +tcp silent.test.", srv);
    /* DoT / DoH / plain DoH */
    char tls[300]; snprintf(tls, sizeof(tls), "@127.0.0.1 -p %d +time=2 +tries=1", s->tls_port);
    const char *tlsopts[] = { "+tls", "+tls +tls-ca", "+tls +tls-ca=%s", "+tls +tls-ca=%s +tls-hostname=localhost", "+tls +tls-ca=%s +tls-hostname=wrong.name",
                              "+https", "+https +tls-ca=%s", "+https-get +tls-ca=%s", "+https-post=/dns-query", "+https=/chk +tls-ca=%s",
                              "+tls +tls-certfile=%s +tls-keyfile=%s", "+tls +keepopen", "+tls +yaml" };
    const char *tlsnames[] = { "ok.test.", "big.test. TXT", "tsig.test.", "chunked.test.", "http404.test.", "badct.test.", "axfr.test. AXFR" };
    for (size_t i = 0; i < N(tlsopts); i++) {
        char o[800]; snprintf(o, sizeof(o), tlsopts[i], g_cert_path, g_key_path);
        for (size_t n = 0; n < N(tlsnames); n++) {
            if (n > 2 && strstr(tlsopts[i], "http") == NULL && n != 6) continue;
            run_line("%s %s %s", tls, o, tlsnames[n]);
        }
    }
    char http[300]; snprintf(http, sizeof(http), "@127.0.0.1 -p %d +time=2 +tries=1", s->http_port);
    const char *httpopts[] = { "+http-plain", "+http-plain-get", "+http-plain-post=/q", "+http-plain=/x", "+http", "+http-get=/g" };
    for (size_t i = 0; i < N(httpopts); i++)
        for (size_t n = 0; n < 6; n++) run_line("%s %s %s", http, httpopts[i], tlsnames[n]);
    run_line("@127.0.0.1 -p %d +https +time=1 +tries=1 ok.test.", s->port);          /* TLS to a non-TLS port */
    run_line("@127.0.0.1 -p 1 +tls +time=1 +tries=1 ok.test.");                        /* connection refused */
    run_line("@127.0.0.1 -p 1 +tcp +time=1 +tries=1 ok.test.");
    /* PROXY v2 header */
    run_line("%s +proxy=192.0.2.1#1234-192.0.2.2#53 +tcp ok.test.", srv);
    run_line("%s +proxy=[2001:db8::1]:1-[2001:db8::2]:2 ok.test.", srv);
    run_line("%s +proxy-plain=bogus ok.test.", srv);
    /* malformed-query generator (--break) and trace/nssearch variants */
    const char *brk[] = { "compression-loop", "compression-forward", "label-too-long", "reserved-length-bits", "oversized-qname",
                          "qdcount=2", "truncated-question", "opt-rdlen=3", "arcount=4", "opcode=9", "qr-bit", "notify-no-question",
                          "too-short=5", "short-header", "update-meta-type" };
    for (size_t i = 0; i < N(brk); i++) run_line("%s --break=%s +tcp ok.test.", srv, brk[i]);
    run_line("%s --break=tcp-length-overclaim=40 +tcp ok.test.", srv);
    run_line("%s --break=tcp-zero-length +tcp ok.test.", srv);
    run_line("%s --break=tcp-idle-hold=1 +tcp ok.test.", srv);
    run_line("%s +trace -y hmac-sha256:tsig-key.:%s www.trace.test.", srv, TSIG_SECRET_B64);
    run_line("%s +trace -4 www.trace.test.", srv);
    run_line("%s +trace -6 www.trace.test.", srv);
    run_line("%s +trace --hex 123401000001000000000000026f6b04746573740000010001", srv);
    run_line("%s +trace --hex=zz", srv);
    run_line("%s +trace silent.trace.test.", srv);
    run_line("@127.0.0.1 -p 1 +trace +time=1 +tries=1 www.trace.test.");
    run_line("@127.0.0.1 -p 1 +trace +yaml +time=1 +tries=1 www.trace.test.");
    run_line("%s +nssearch -y hmac-sha256:tsig-key.:%s nss.test.", srv, TSIG_SECRET_B64);
    run_line("%s +nssearch --hex 123401000001000000000000036e737304746573740000020001", srv);
    run_line("%s +nssearch --hex=zz nss.test.", srv);
    run_line("@127.0.0.1 -p 1 +nssearch +time=1 +tries=1 nss.test.");
    /* reused +keepopen connections that the server has closed (TCP, DoT, DoH) */
    run_line("%s +keepopen +tcp closeafter.test. ok.test. closeafter.test. ok.test.", srv);
    run_line("%s +keepopen +tls closeafter.test. ok.test. closeafter.test. big.test. TXT", tls);
    run_line("%s +keepopen +https closeafter.test. ok.test. ok.test.", tls);
    run_line("%s +keepopen +https-get ok.test. ok.test.", tls);
    run_line("%s +keepopen +tcp -b 127.0.0.1 ok.test. ok.test.", srv);
    /* BADCOOKIE / BADVERS retries over DoT and DoH */
    run_line("%s +tls badcookie.test. +cookie", tls);
    run_line("%s +https badcookie.test. +cookie", tls);
    run_line("%s +tls +edns=1 badvers.test.", tls);
    run_line("%s +https +edns=1 badvers.test.", tls);
    run_line("%s +tcp +edns=1 badvers.test.", srv);
    run_line("%s +tcp badcookie.test. +cookie", srv);
    /* TCP socket options and source-address binding */
    run_line("%s +tcp-mss=1200 +tcp-window=65536 ok.test.", srv);
    run_line("%s +tcp -b 127.0.0.1#0 ok.test.", srv);
    run_line("%s +tcp -b ::1 ok.test.", srv);
    run_line("%s +tcp -b no-such-host.invalid ok.test.", srv);
    run_line("%s -b no-such-host.invalid ok.test.", srv);
    run_line("%s -b ::1 ok.test.", srv);
    run_line("%s -b 192.0.2.254 ok.test.", srv);
    run_line("%s +tcp -b 192.0.2.254 ok.test.", srv);
    run_line("%s +tls -b 127.0.0.1 ok.test.", tls);
    run_line("%s --break=too-short=-1 +tcp ok.test.", srv);
    run_line("%s --break=too-short=0 +tcp ok.test.", srv);
    run_line("%s --break=too-short=2 ok.test.", srv);
    run_line("%s --break=tcp-idle-hold=5 +tcp ok.test.", srv);
    run_line("%s +https-get +tls-ca=%s big%s.test.", tls, g_cert_path,
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    run_line("%s +trace tc.test. A", srv);
    run_line("%s +nssearch tc.test.", srv);
    run_line("@localhost -p %d +time=1 +tries=1 +tls ok.test.", s->tls_port);
    run_line("@[::1] -p %d +time=1 +tries=1 +tls ok.test.", s->tls_port);
    run_line("@127.0.0.1. -p %d +time=1 +tries=1 +tls +tls-ca=%s ok.test.", s->tls_port, g_cert_path);
    run_line("@[127.0.0.1] -p %d +time=1 +tries=1 +tls +tls-ca=%s ok.test.", s->tls_port, g_cert_path);
    run_line("@localhost. -p %d +time=1 +tries=1 +tls +tls-ca=%s ok.test.", s->tls_port, g_cert_path);
    run_line("%s +tls +tls-ca=%s +tls-hostname=[::1] ok.test.", tls, g_cert_path);
    run_line("%s +tls +tls-ca=%s +tls-hostname=localhost. ok.test.", tls, g_cert_path);
    run_line("%s +https +tls-ca=%s +tls-hostname=localhost. ok.test.", tls, g_cert_path);
    /* --test-all and misc */
    run_line("%s --test-all ok.test.", srv);
    run_line("%s --break=truncated-length +tcp ok.test.", srv);
    run_line("%s --break=bogus ok.test.", srv);
    run_line("%s --hex 123401000001000000000000026f6b04746573740000010001", srv);
    run_line("%s --hex=zz", srv);
    run_line("%s -m +short ok.test.", srv);
    run_line("%s +search +domain=test. ok", srv);
    run_line("%s +idnin +idnout bücher.test.", srv);
    run_line("%s +fuzztime=1 -y hmac-sha256:tsig-key.:%s tsig.test.", srv, TSIG_SECRET_B64);
    run_line("-v");
    run_line("-h");
    run_line("%s", "");
    printf("  -> %d dag runs (%d non-zero exits).\n", g_runs, g_nonzero);
}

/* ======================================================================
 * --replay inputs: PCAP (several link types), dnstap frame streams, text
 * ==================================================================== */
static size_t mk_query(uint8_t *p, uint16_t id, const char *name, uint16_t type, bool resp) {
    memset(p, 0, 12); p[0] = (uint8_t)(id >> 8); p[1] = (uint8_t)id; p[2] = resp ? 0x84 : 0x01; p[5] = 1;
    size_t o = put_name(p, 12, 512, name); p[o++] = (uint8_t)(type >> 8); p[o++] = (uint8_t)type; p[o++] = 0; p[o++] = 1;
    if (resp) { p[7] = 1; uint8_t a4[4] = { 192, 0, 2, 1 }; o = put_rr(p, o, 512, name, 1, 300, a4, 4); }
    return o;
}
static void pcap_hdr(FILE *f, uint32_t linktype, bool swapped) {
    uint32_t magic = 0xa1b2c3d4, snap = 65535; uint16_t vmaj = 2, vmin = 4; uint32_t z = 0;
    if (swapped) { magic = __builtin_bswap32(magic); vmaj = __builtin_bswap16(vmaj); vmin = __builtin_bswap16(vmin); snap = __builtin_bswap32(snap); linktype = __builtin_bswap32(linktype); }
    fwrite(&magic, 4, 1, f); fwrite(&vmaj, 2, 1, f); fwrite(&vmin, 2, 1, f); fwrite(&z, 4, 1, f); fwrite(&z, 4, 1, f); fwrite(&snap, 4, 1, f); fwrite(&linktype, 4, 1, f);
}
static void pcap_rec(FILE *f, const uint8_t *d, uint32_t n, bool swapped) {
    uint32_t h[4] = { 1700000000, 0, n, n };
    if (swapped) for (int i = 0; i < 4; i++) h[i] = __builtin_bswap32(h[i]);
    fwrite(h, 4, 4, f); fwrite(d, 1, n, f);
}
static size_t l3l4(uint8_t *b, bool v6, bool tcp, bool to_server, const uint8_t *dns, size_t dl) {
    size_t o = 0;
    size_t l4 = tcp ? 20 + 2 + dl : 8 + dl;
    if (!v6) {
        b[o++] = 0x45; b[o++] = 0; b[o++] = (uint8_t)((20 + l4) >> 8); b[o++] = (uint8_t)(20 + l4); memset(b + o, 0, 4); o += 4;
        b[o++] = 64; b[o++] = tcp ? 6 : 17; b[o++] = 0; b[o++] = 0;
        uint8_t a[4] = { 10, 0, 0, 1 }, s[4] = { 10, 0, 0, 53 };
        memcpy(b + o, to_server ? a : s, 4); o += 4; memcpy(b + o, to_server ? s : a, 4); o += 4;
    } else {
        b[o++] = 0x60; b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = (uint8_t)(l4 >> 8); b[o++] = (uint8_t)l4; b[o++] = tcp ? 6 : 17; b[o++] = 64;
        memset(b + o, 0, 32); b[o + 15] = to_server ? 1 : 53; b[o + 31] = to_server ? 53 : 1; o += 32;
    }
    uint16_t sp = to_server ? 5353 : 53, dp = to_server ? 53 : 5353;
    b[o++] = (uint8_t)(sp >> 8); b[o++] = (uint8_t)sp; b[o++] = (uint8_t)(dp >> 8); b[o++] = (uint8_t)dp;
    if (tcp) { memset(b + o, 0, 16); b[o + 8] = 0x50; b[o + 9] = 0x18; o += 16; b[o++] = (uint8_t)(dl >> 8); b[o++] = (uint8_t)dl; }
    else { b[o++] = (uint8_t)(l4 >> 8); b[o++] = (uint8_t)l4; b[o++] = 0; b[o++] = 0; }
    memcpy(b + o, dns, dl); return o + dl;
}
static void write_pcap(const char *path, uint32_t linktype, bool swapped) {
    FILE *f = fopen(path, "wb"); pcap_hdr(f, linktype, swapped);
    const char *names[] = { "ok.test.", "diffextra.test.", "diffrc.test.", "big.test.", "nxdomain.test.", "silent.test.", "tc.test." };
    for (int i = 0; i < 14; i++) {
        uint8_t dns[600], pkt[1000], fr[1100]; bool v6 = i & 1, tcp = (i % 3) == 2;
        for (int dir = 0; dir < 2; dir++) {
            size_t dl = mk_query(dns, (uint16_t)(0x100 + i), names[i % 7], i % 4 == 3 ? 16 : 1, dir == 1);
            size_t pl = l3l4(pkt, v6, tcp, dir == 0, dns, dl);
            size_t fl = 0;
            if (linktype == 1) { memset(fr, 0, 12); if (i % 5 == 4) { fr[12] = 0x81; fr[13] = 0; fr[14] = 0; fr[15] = 5; fr[16] = v6 ? 0x86 : 0x08; fr[17] = v6 ? 0xDD : 0x00; fl = 18; } else { fr[12] = v6 ? 0x86 : 0x08; fr[13] = v6 ? 0xDD : 0x00; fl = 14; } }
            else if (linktype == 113) { memset(fr, 0, 16); fr[14] = v6 ? 0x86 : 0x08; fr[15] = v6 ? 0xDD : 0x00; fl = 16; }
            else if (linktype == 0) { uint32_t fam = v6 ? 24 : 2; memcpy(fr, &fam, 4); fl = 4; }
            memcpy(fr + fl, pkt, pl); fl += pl;
            pcap_rec(f, fr, (uint32_t)fl, swapped);
        }
    }
    uint8_t junk[3] = { 1, 2, 3 }; pcap_rec(f, junk, 3, swapped);
    fclose(f);
}
static size_t pb_msg(uint8_t *out, size_t cap, int mtype, const uint8_t *q, size_t ql, const uint8_t *r, size_t rlen, int proto) {
    uint8_t m[2048]; size_t o = 0;
    o += pb_encode_varint_field(m + o, sizeof(m) - o, 1, (uint64_t)mtype);
    o += pb_encode_varint_field(m + o, sizeof(m) - o, 2, 1);
    o += pb_encode_varint_field(m + o, sizeof(m) - o, 3, (uint64_t)proto);
    uint8_t ip[4] = { 10, 0, 0, 1 }; o += pb_encode_bytes_field(m + o, sizeof(m) - o, 4, ip, 4);
    if (q) o += pb_encode_bytes_field(m + o, sizeof(m) - o, 10, q, ql);
    if (r) o += pb_encode_bytes_field(m + o, sizeof(m) - o, 14, r, rlen);
    size_t d = 0;
    d += pb_encode_bytes_field(out + d, cap - d, 1, (const uint8_t *)"id", 2);
    d += pb_encode_varint_field(out + d, cap - d, 15, 1);
    d += pb_encode_bytes_field(out + d, cap - d, 14, m, o);
    return d;
}
static void write_dnstap(const char *path) {
    FILE *f = fopen(path, "wb");
    const char ct[] = "protobuf:dnstap.Dnstap";
    uint32_t hdr[5] = { 0, htonl(4 + 4 + 4 + 22), htonl(2), htonl(1), htonl(22) };
    fwrite(hdr, 4, 5, f); fwrite(ct, 1, 22, f);
    const char *names[] = { "ok.test.", "diffextra.test.", "diffrc.test.", "big.test." };
    for (int i = 0; i < 10; i++) {
        uint8_t q[600], r[600], fr[2048];
        size_t ql = mk_query(q, (uint16_t)(0x200 + i), names[i % 4], 1, false);
        size_t rl = mk_query(r, (uint16_t)(0x200 + i), names[i % 4], 1, true);
        int mt = (i % 3 == 0) ? 5 : (i % 3 == 1 ? 6 : 1);      /* CLIENT_QUERY / CLIENT_RESPONSE / AUTH_QUERY */
        size_t fl = pb_msg(fr, sizeof(fr), mt, (mt != 6) ? q : NULL, ql, (mt != 5) ? r : NULL, rl, (i & 1) ? 2 : 1);
        uint32_t be = htonl((uint32_t)fl); fwrite(&be, 4, 1, f); fwrite(fr, 1, fl, f);
    }
    uint32_t junk = htonl(5); fwrite(&junk, 4, 1, f); fwrite("\x0a\x03\x01\x02\x03", 1, 5, f);
    uint32_t stop[3] = { 0, htonl(4), htonl(3) }; fwrite(stop, 4, 3, f);
    fclose(f);
}

static void test_replay(fsrv_t *s, fsrv_t *s2) {
    printf("[TEST] net sweep: --replay over pcap / dnstap / text inputs...\n");
    char p1[400], p2[400], p3[400], p4[400], p5[400], p6[400], out[400];
    snprintf(p1, sizeof(p1), "%s/a.pcap", g_tmp); write_pcap(p1, 1, false);
    snprintf(p2, sizeof(p2), "%s/b.pcap", g_tmp); write_pcap(p2, 113, true);
    snprintf(p3, sizeof(p3), "%s/c.pcap", g_tmp); write_pcap(p3, 101, false);
    snprintf(p6, sizeof(p6), "%s/d.pcap", g_tmp); write_pcap(p6, 0, false);
    snprintf(p4, sizeof(p4), "%s/t.dnstap", g_tmp); write_dnstap(p4);
    snprintf(p5, sizeof(p5), "%s/q.txt", g_tmp);
    FILE *f = fopen(p5, "w"); fprintf(f, "ok.test. A\ndiffextra.test. A\ndiffrc.test. AAAA\n# c\n\nbig.test. TXT\nbad line with too many tokens here\nx.test. BOGUS\n"); fclose(f);
    snprintf(out, sizeof(out), "%s/diff.out", g_tmp);
    const char *inputs[] = { p1, p2, p3, p6, p4, p5, "/nonexistent/file" };
    for (size_t i = 0; i < N(inputs); i++) {
        run_line("--replay %s --server1 127.0.0.1:%d --timeout-ms 300", inputs[i], s->port);
        run_line("--replay %s --server1 127.0.0.1:%d --server2 127.0.0.1:%d --timeout-ms 300 --output json --output-diff %s", inputs[i], s->port, s2->port, out);
        run_line("--replay %s --server1 127.0.0.1:%d --compare-recorded --ignore-ttl --workers 3 --rate 500 --timeout-ms 300", inputs[i], s->port);
        run_line("--replay %s --server1 127.0.0.1:%d --server2 127.0.0.1:%d --transport tcp --stop-after 1 --max-queries 5 --timeout-ms 300 +dnssec", inputs[i], s->port, s2->port);
        run_line("--replay %s --server1 127.0.0.1:%d --server1-transport tcp --server2 127.0.0.1:%d --server2-transport udp --output text --diff --timeout-ms 300 +nodnssec", inputs[i], s->port, s2->port);
    }
    run_line("--replay");
    run_line("--replay %s", p1);
    run_line("--replay %s --server1 [::1]:1 --timeout-ms 100 --workers 99 --output yaml", p5);
    run_line("--replay %s --server1 127.0.0.1:notaport --bogus-option", p5);
    printf("  -> replay runs done.\n");
}

/* ======================================================================
 * Direct calls into the dag client helpers (packet builder, proxy header,
 * HTTP body decoder, address resolution) with edge-case inputs.
 * ==================================================================== */
static void test_client_helpers(void) {
    printf("[TEST] net sweep: dag client helpers...\n");
    for (int a = 0; a < 256; a++) (void)dnssec_algo_name((uint8_t)a);
    const char *subnets[] = { "0", "0/0", "::/0", "192.0.2.0/24", "192.0.2.1/33", "2001:db8::/129", "2001:db8::1/61", "bogus", "1.2.3.4",
                              "10.0.0.0/0", "10.1.2.3/7", "::1", "/8", "" };
    for (size_t i = 0; i < N(subnets); i++) { query_opts_t qo; memset(&qo, 0, sizeof(qo)); (void)parse_subnet_arg(subnets[i], &qo); }
    const char *brk[] = { "compression-loop", "compression-forward", "label-too-long", "reserved-length-bits", "oversized-qname",
                          "qdcount=3", "truncated-question", "opt-rdlen=5", "arcount=9", "opcode=15", "qr-bit", "notify-no-question",
                          "too-short=4", "short-header", "tcp-length-overclaim=100", "tcp-zero-length", "tcp-idle-hold=1",
                          "update-meta-type", "nonsense" };
    for (int round = 0; round < 3; round++) for (size_t i = 0; i < N(brk); i++) parse_break_arg(brk[i]);
    print_break_help();
    {   /* build queries while every break kind is active */
        query_opts_t bq; memset(&bq, 0, sizeof(bq)); bq.qid_override = -1; bq.opcode_override = -1; bq.edns_version = 0;
        uint8_t bp[1024];
        for (size_t cap = 0; cap < 80; cap += 5) (void)build_query_packet(bp, cap, "ok.test.", 1, &bq);
        (void)build_query_packet(bp, sizeof(bp), "ok.test.", 1, &bq);
        g_break_count = 0;
    }
    /* the packet builder with every update/prereq form, under shrinking buffers */
    query_opts_t qo; memset(&qo, 0, sizeof(qo));
    qo.qid_override = -1; qo.rd_flag = qo.aa_flag = qo.tc_flag = qo.ra_flag = qo.ad_flag = qo.cd_flag = qo.z_flag = true;
    qo.opcode_override = -1;
    const char *adds[] = { "a.upd.test. 300 A 192.0.2.1", "b.upd.test. IN 60 TXT \"quoted text\" \"two\"", "c.upd.test. 60 IN TXT \"esc\\\"aped\\\\\"",
                           "d.upd.test. BOGUSTYPE x", "e.upd.test.", "f.upd.test. 60 A not-an-ip", "g.upd.test. IN MX 10 mail.test.",
                           "\"quoted name\" 60 A 192.0.2.1", "h.upd.test. 3600 CH TXT \"ch\"" };
    for (size_t i = 0; i < N(adds) && qo.update_op_count < MAX_UPDATE_OPS; i++) {
        qo.update_ops[qo.update_op_count].kind = (update_op_kind_t)(i % 3);
        qo.update_ops[qo.update_op_count].raw = strdup(adds[i]); qo.update_op_count++;
    }
    const struct { prereq_kind_t k; const char *n, *t, *rd; } pre[] = {
        { PREREQ_NXDOMAIN, "a.upd.test.", "", "" }, { PREREQ_YXDOMAIN, "b.upd.test.", "", "" },
        { PREREQ_NXRRSET, "c.upd.test.", "A", "" }, { PREREQ_NXRRSET, "c.upd.test.", "BOGUS", "" },
        { PREREQ_YXRRSET, "d.upd.test.", "TXT", "\"q u\" \"x\\\"y\"" }, { PREREQ_YXRRSET, "d.upd.test.", "A", "bad-ip" },
        { PREREQ_YXRRSET, "d.upd.test.", "BOGUS", "x" }, { PREREQ_YXRRSET, "e.upd.test.", "A", "" },
        { (prereq_kind_t)9, "f.upd.test.", "A", "" },
        { PREREQ_NXDOMAIN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.", "", "" },
    };
    for (size_t i = 0; i < N(pre) && qo.prereq_count < MAX_PREREQS; i++) {
        qo.prereqs[qo.prereq_count].kind = pre[i].k;
        snprintf(qo.prereqs[qo.prereq_count].name, sizeof(qo.prereqs[0].name), "%s", pre[i].n);
        snprintf(qo.prereqs[qo.prereq_count].type_str, sizeof(qo.prereqs[0].type_str), "%s", pre[i].t);
        snprintf(qo.prereqs[qo.prereq_count].rdata, sizeof(qo.prereqs[0].rdata), "%s", pre[i].rd);
        qo.prereq_count++;
    }
    uint8_t pkt[4096], mac[64]; size_t ml;
    for (size_t cap = 12; cap < 700; cap += 7) (void)build_query_packet(pkt, cap, "upd.test.", 6, &qo);
    qo.want_tsig = true; qo.tsig_key.name = "tsig-key."; qo.tsig_key.algorithm = "hmac-sha512";
    memcpy(qo.tsig_key.secret_decoded, "k", 1); qo.tsig_key.secret_decoded_len = 1;
    (void)build_query_packet(pkt, sizeof(pkt), "upd.test.", 6, &qo);
    qo.tsig_key.algorithm = "hmac-md5"; (void)build_and_sign_query(pkt, sizeof(pkt), "upd.test.", 6, &qo, mac, &ml);
    qo.tsig_key.algorithm = NULL; qo.tsig_key.name = NULL; (void)build_query_packet(pkt, sizeof(pkt), "upd.test.", 6, &qo);
    (void)build_query_packet(pkt, sizeof(pkt), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.", 1, &qo);
    for (int i = 0; i < qo.update_op_count; i++) free(qo.update_ops[i].raw);
    /* EDNS option display for every option code with truncated bodies */
    display_opts_t d; memset(&d, 0, sizeof(d));
    uint8_t ob[64]; for (int i = 0; i < 64; i++) ob[i] = (uint8_t)(i * 37);
    int saved = dup(1); int dn = open("/dev/null", O_WRONLY); fflush(stdout); dup2(dn, 1);
    for (int code = 0; code < 26; code++) for (int len = 0; len < 24; len += 3) {
        decode_and_print_edns_option(ob, 0, (uint16_t)code, (uint16_t)len, (code & 1) ? "  " : NULL, &d);
        d.yaml = len & 1; d.multiline = code & 2;
    }
    decode_and_print_edns_option(ob, 0, 65001, 8, "", &d);
    fflush(stdout); dup2(saved, 1); close(saved); close(dn);
    /* PROXY v2 */
    const char *proxies[] = { "", NULL, "192.0.2.1#1-192.0.2.2#53", "2001:db8::1#5-2001:db8::2", "192.0.2.1-2001:db8::2", "nodash", "x-y" };
    for (size_t i = 0; i < N(proxies); i++) {
        query_opts_t q2; memset(&q2, 0, sizeof(q2));
        if (parse_proxy_arg(proxies[i], &q2)) { q2.use_proxy = true;
            for (int tcp = 0; tcp < 2; tcp++) { (void)build_proxyv2_header(pkt, sizeof(pkt), &q2, tcp); (void)build_proxyv2_header(pkt, 10, &q2, tcp); } }
    }
    /* HTTP response bodies */
    const char *bodies[] = {
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd", "HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nabcd",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2;ext=1\r\nab\r\nzz\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\nab", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab",
        "HTTP/1.1 404 Not Found\r\n\r\n", "HTTP/1.0 200\r\n\r\nxyz", "garbage-without-header-end-xxxx", "HTTP/1.1 2x0 OK\r\n\r\nbody",
        "HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nab", "HTTP/1.1 200 OK\r\nX: y\r\n\r\n",
    };
    for (size_t i = 0; i < N(bodies); i++) {
        uint8_t out[128];
        (void)decode_http_response_body((const uint8_t *)bodies[i], strlen(bodies[i]), out, sizeof(out));
        (void)decode_http_response_body((const uint8_t *)bodies[i], strlen(bodies[i]), out, 1);
    }
    (void)decode_http_response_body(NULL, 0, pkt, 1);
    /* address resolution through getaddrinfo */
    struct sockaddr_storage ss; socklen_t sl; int fam;
    const char *hosts[] = { "localhost", "127.0.0.1", "::1", "nonexistent.invalid", "" };
    for (size_t i = 0; i < N(hosts); i++) for (int pf = 0; pf < 3; pf++) {
        int pref = pf == 0 ? AF_UNSPEC : pf == 1 ? AF_INET : AF_INET6;
        (void)resolve_server_addr(hosts[i], 53, pref, &ss, &sl, &fam, i & 1);
        (void)get_server_addr_count(hosts[i], 53, pref);
    }
    printf("  -> client helpers done.\n");
}

int main(void) {
    printf("=== dag Network Coverage Sweep Tests ===\n");
    signal(SIGPIPE, SIG_IGN);
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/kdag_net_XXXXXX");
    if (!mkdtemp(g_tmp)) { perror("mkdtemp"); return 1; }
    make_cert();
    make_keys();
    memset(&g_srv_key, 0, sizeof(g_srv_key));
    g_srv_key.name = "tsig-key."; g_srv_key.algorithm = "hmac-sha256";
    memcpy(g_srv_key.secret_decoded, "secretsecretsecretsecret", 24); g_srv_key.secret_decoded_len = 24;
    static fsrv_t s1, s2;
    fs_start(&s1, 0);
    fs_start(&s2, 1);
    test_key_files();
    {   /* helpers mutate dag's global break list: run them in a child so the CLI matrix starts clean */
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) { test_client_helpers(); fflush(stdout); exit(0); }
        int st = 0; waitpid(pid, &st, 0);
        assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    test_dag_cli_matrix(&s1, &s2);
    test_replay(&s1, &s2);
    g_stop = 1;
    pthread_join(s1.thr, NULL); pthread_join(s2.thr, NULL);
    printf("=== All dag Network Coverage Sweep Tests PASSED ===\n");
    return 0;
}

/*
 * test_server_stmt.c - server <prefix> { ... } and key { } in view { } (BIND compatibility, batch 5), and the port of nested primaries lists.
 *
 * Expectations are worked out from the BIND 9.20 source (v9.20.4) by hand for each case:
 *   lib/isccfg/namedconf.c      server_clauses (the options), cfg_parse_netprefix_map(), parse_server_key_kludge() (keys, with or without braces)
 *   lib/isccfg/check.c          check_servers() (extra prefix bits, "-v6 not legal", "already exists previous definition", "unknown key"),
 *                               check_keylist() (a view's keys are checked together with the global ones: a second key of a name is an error)
 *   bin/named/server.c          configure_peer() (clamps: edns-udp-size and max-udp-size 512..4096, edns-version <= 255, padding <= 512),
 *                               named_config_get(cfgmaps, "server") (the first map that has the statement: a view's list replaces the global one)
 *   bin/named/tsigconf.c        named_tsigkeyring_fromconfig() (the ring of a view = the global keys + the view's own)
 *   lib/dns/peer.c              dns_peerlist_addpeer() (more specific prefixes first), dns_peerlist_peerbyaddr() (first that covers the address)
 *   lib/dns/zone.c              soa_query(), notify_send_toaddr(), zone_xfrdone start (the key of the primaries element, then the server's; the server's
 *                               transfer-source / notify-source beat the list's `source`; request-ixfr / request-expire / transfers of the peer)
 *   lib/ns/xfrout.c, client.c   provide-ixfr, transfer-format, max-udp-size of the peer
 *   bin/named/config.c          named_config_getipandkeylist() (an element of a nested list without a port takes the enclosing list's port;
 *                               sources are not inherited)
 * Addresses are documentation addresses (RFC 5737, RFC 3849).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../dns_config_parser.h"
#include "../dns_tsig_acl.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static int g_checks = 0;
static int g_failed = 0;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { g_failed++; printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

/* parse with stderr (the [ERROR] / [WARNING] lines) collected in err; returns whether the parse succeeded */
static bool parse_cap(const char *text, server_config_t *cfg, char *err, size_t errsz) {
    char path[] = "/tmp/karidns-srvstmt-test.XXXXXX";
    int fd = mkstemp(path);
    int saved = dup(2);
    err[0] = '\0';
    memset(cfg, 0, sizeof(*cfg));
    if (fd < 0 || saved < 0) return parse_named_conf(text, cfg) == 0;
    fflush(stderr);
    dup2(fd, 2);
    bool ok = parse_named_conf(text, cfg) == 0;
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    lseek(fd, 0, SEEK_SET);
    ssize_t r = read(fd, err, errsz - 1);
    err[r > 0 ? r : 0] = '\0';
    close(fd);
    unlink(path);
    return ok;
}

static bool fails_with(const char *text, const char *frag) {
    server_config_t c;
    char err[4096];
    bool ok = parse_cap(text, &c, err, sizeof(err));
    if (ok) {
        free_server_config_fields(&c);
        printf("  [info] parse unexpectedly succeeded: %s\n", text);
        return false;
    }
    free_server_config_fields(&c);
    if (!strstr(err, frag)) {
        printf("  [info] message lacks '%s': %s\n", frag, err);
        return false;
    }
    return true;
}

static bool v4(const char *s, uint8_t out[4]) { return inet_pton(AF_INET, s, out) == 1; }
static bool v6(const char *s, uint8_t out[16]) { return inet_pton(AF_INET6, s, out) == 1; }

static const server_stmt_t *find4(const server_config_t *c, const char *view, const char *ip) {
    uint8_t a[4];
    return v4(ip, a) ? config_server_find(c, view, AF_INET, a) : NULL;
}
static const server_stmt_t *find6(const server_config_t *c, const char *view, const char *ip) {
    uint8_t a[16];
    return v6(ip, a) ? config_server_find(c, view, AF_INET6, a) : NULL;
}

#define KEYA "c2VjcmV0LWEtc2VjcmV0LWEtc2VjcmV0LWEtMTIzNDU2Nzg="
#define KEYB "c2VjcmV0LWItc2VjcmV0LWItc2VjcmV0LWItMTIzNDU2Nzg="
#define KEYDEF(name, sec) "key \"" name "\" { algorithm hmac-sha256; secret \"" sec "\"; };\n"

static void test_parse_options(void) {
    printf("[TEST] every option of a server statement...\n");
    server_config_t c;
    char err[4096];
    const char *conf =
        KEYDEF("k1", KEYA)
        "server 192.0.2.0/24 {\n"
        "  bogus yes; edns no; edns-udp-size 1400; edns-version 1; keys k1; max-udp-size 1200; notify-source 192.0.2.5;\n"
        "  padding 128; provide-ixfr no; request-expire no; request-ixfr no; request-nsid yes; require-cookie yes; send-cookie no;\n"
        "  tcp-keepalive yes; tcp-only yes; transfer-format one-answer; transfer-source 192.0.2.6; transfers 7;\n"
        "  query-source address 192.0.2.7 port 5300;\n"
        "};\n"
        "server 2001:db8::/32 { keys { k1; }; transfer-source-v6 2001:db8::5; notify-source-v6 *; transfer-format many-answers; };\n"
        "server 198.51.100.1 { keys { k1 }; };\n"
        "zone \"a.test\" { type master; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    const server_stmt_t *s = find4(&c, NULL, "192.0.2.77");
    CHECK(s != NULL && s->family == AF_INET && s->plen == 24);
    if (s) {
        CHECK((s->set & SV_B_BOGUS) && (s->bools & SV_B_BOGUS));
        CHECK((s->set & SV_B_EDNS) && !(s->bools & SV_B_EDNS));
        CHECK((s->set & SV_EDNS_UDP_SIZE) && s->edns_udp_size == 1400);
        CHECK((s->set & SV_EDNS_VERSION) && s->edns_version == 1);
        CHECK((s->set & SV_KEYS) && s->key && strcmp(s->key, "k1") == 0);
        CHECK((s->set & SV_MAX_UDP_SIZE) && s->max_udp_size == 1200);
        CHECK((s->set & SV_PADDING) && s->padding == 128);
        CHECK((s->xo.set & XO_B_PROVIDE_IXFR) && !(s->xo.bools & XO_B_PROVIDE_IXFR));
        CHECK((s->xo.set & XO_B_REQUEST_EXPIRE) && !(s->xo.bools & XO_B_REQUEST_EXPIRE));
        CHECK((s->xo.set & XO_B_REQUEST_IXFR) && !(s->xo.bools & XO_B_REQUEST_IXFR));
        CHECK((s->set & SV_B_REQUEST_NSID) && (s->bools & SV_B_REQUEST_NSID));
        CHECK((s->set & SV_B_REQUIRE_COOKIE) && (s->bools & SV_B_REQUIRE_COOKIE));
        CHECK((s->set & SV_B_SEND_COOKIE) && !(s->bools & SV_B_SEND_COOKIE));
        CHECK((s->set & SV_B_TCP_KEEPALIVE) && (s->bools & SV_B_TCP_KEEPALIVE));
        CHECK((s->set & SV_B_TCP_ONLY) && (s->bools & SV_B_TCP_ONLY));
        CHECK((s->set & SV_TRANSFER_FORMAT) && (s->bools & SV_B_ONE_ANSWER));
        CHECK((s->set & SV_TRANSFERS) && s->transfers == 7);
        uint8_t want[4];
        CHECK(v4("192.0.2.5", want) && s->xo.src[XSRC_NOTIFY4].state == 1 && memcmp(s->xo.src[XSRC_NOTIFY4].addr, want, 4) == 0);
        CHECK(v4("192.0.2.6", want) && s->xo.src[XSRC_XFER4].state == 1 && memcmp(s->xo.src[XSRC_XFER4].addr, want, 4) == 0);
    }
    /* padding 128 is in range; the clamps are tested below.  Warnings: options with no effect on an authoritative server */
    CHECK(strstr(err, "bogus is accepted, no effect in KariDNS") != NULL);
    CHECK(strstr(err, "tcp-only is accepted, no effect in KariDNS") != NULL);
    CHECK(strstr(err, "tcp-keepalive is accepted, no effect in KariDNS") != NULL);
    CHECK(strstr(err, "padding is accepted, no effect in KariDNS") != NULL);
    CHECK(strstr(err, "send-cookie is accepted, no effect in KariDNS") != NULL);
    CHECK(strstr(err, "require-cookie is accepted, no effect in KariDNS") != NULL);
    CHECK(strstr(err, "query-source is accepted, no effect in KariDNS") != NULL);
    /* the ones that have an effect are not warned about */
    CHECK(strstr(err, "transfers is accepted") == NULL && strstr(err, "keys is accepted") == NULL && strstr(err, "edns is accepted") == NULL &&
          strstr(err, "request-nsid is accepted") == NULL && strstr(err, "max-udp-size is accepted") == NULL &&
          strstr(err, "transfer-format is accepted") == NULL);
    /* the warnings name the file position of the option: this is a string, so "line N" */
    CHECK(strstr(err, "line 3: server '192.0.2.0/24'") != NULL || strstr(err, "line 7: server '192.0.2.0/24'") != NULL);
    s = find6(&c, NULL, "2001:db8:1::1");
    CHECK(s != NULL && s->family == AF_INET6 && s->plen == 32 && s->key && strcmp(s->key, "k1") == 0);
    if (s) {
        uint8_t want[16];
        CHECK(v6("2001:db8::5", want) && s->xo.src[XSRC_XFER6].state == 1 && memcmp(s->xo.src[XSRC_XFER6].addr, want, 16) == 0);
        CHECK(s->xo.src[XSRC_NOTIFY6].state == 2);     /* `*` */
        CHECK((s->set & SV_TRANSFER_FORMAT) && !(s->bools & SV_B_ONE_ANSWER));
    }
    s = find4(&c, NULL, "198.51.100.1");
    CHECK(s != NULL && s->plen == 32 && s->key && strcmp(s->key, "k1") == 0);   /* `keys { k1 }` : no ';' before '}' */
    CHECK(find4(&c, NULL, "198.51.100.2") == NULL && find4(&c, NULL, "203.0.113.1") == NULL && find6(&c, NULL, "2001:db9::1") == NULL);
    CHECK(c.any_server_max_udp);
    free_server_config_fields(&c);
}

static void test_clamps(void) {
    printf("[TEST] values are brought into range (configure_peer)...\n");
    server_config_t c;
    char err[4096];
    CHECK(parse_cap("server 192.0.2.1 { edns-udp-size 100; max-udp-size 9000; edns-version 999; padding 600; transfers 0; };\n"
                    "server 192.0.2.2 { edns-udp-size 9000; max-udp-size 100; };\n"
                    "zone \"a.test\" { type master; };\n", &c, err, sizeof(err)));
    const server_stmt_t *s = find4(&c, NULL, "192.0.2.1");
    CHECK(s && s->edns_udp_size == 512 && s->max_udp_size == 4096 && s->edns_version == 255 && s->padding == 512 && s->transfers == 0 &&
          (s->set & SV_TRANSFERS));
    CHECK(strstr(err, "padding cannot exceed 512") != NULL);
    s = find4(&c, NULL, "192.0.2.2");
    CHECK(s && s->edns_udp_size == 4096 && s->max_udp_size == 512);
    free_server_config_fields(&c);
}

static void test_parse_errors(void) {
    printf("[TEST] errors of a server statement, with the place...\n");
    CHECK(fails_with("server 192.0.2.1 { frobnicate yes; };", "unknown option 'frobnicate'"));
    CHECK(fails_with("server 192.0.2.1 { frobnicate yes; };", "line 1"));
    CHECK(fails_with("server 192.0.2.1 { request-sit yes; };", "option 'request-sit' no longer exists"));
    CHECK(fails_with("server 192.0.2.1 { support-ixfr yes; };", "option 'support-ixfr' no longer exists"));
    CHECK(fails_with("server 192.0.2.1 { bogus yes; bogus no; };", "duplicate 'bogus' option"));
    CHECK(fails_with("server 192.0.2.1 { bogus maybe; };", "invalid bogus value"));
    CHECK(fails_with("server 192.0.2.1 { transfers many; };", "invalid transfers value"));
    CHECK(fails_with("server 192.0.2.1 { transfers 4294967296; };", "invalid transfers value"));
    CHECK(fails_with("server 192.0.2.1 { transfer-format some-answers; };", "invalid transfer-format value"));
    CHECK(fails_with("server 192.0.2.1 { keys { a; b; }; };", "'keys' takes one key name"));
    CHECK(fails_with("server 192.0.2.1 { keys; };", "expected a key name after 'keys'"));
    CHECK(fails_with("server 192.0.2.1 { query-source; };", "expected an address after 'query-source'"));
    CHECK(fails_with("server 192.0.2.1 { bogus yes };", "expected ';'"));
    CHECK(fails_with("server 192.0.2.1 bogus yes;", "expected '{'"));
    CHECK(fails_with("server { bogus yes; };", "expected an address or prefix"));
    CHECK(fails_with("server not-an-address { };", "is not an address or prefix"));
    CHECK(fails_with("server 192.0.2.1/33 { };", "prefix length that is too long"));
    CHECK(fails_with("server 192.0.2.1/x { };", "no valid prefix length"));
    CHECK(fails_with("server 192.0.2.1/24 { };", "invalid prefix (extra bits specified)"));
    CHECK(fails_with("server 2001:db8::1/32 { };", "invalid prefix (extra bits specified)"));
    CHECK(fails_with("server 192.0.2.1 { transfer-source-v6 2001:db8::1; };", "transfer-source-v6 is not legal for an IPv4 server"));
    CHECK(fails_with("server 192.0.2.1 { notify-source-v6 2001:db8::1; };", "notify-source-v6 is not legal for an IPv4 server"));
    CHECK(fails_with("server 2001:db8::1 { transfer-source 192.0.2.1; };", "transfer-source is not legal for an IPv6 server"));
    CHECK(fails_with("server 2001:db8::1 { notify-source 192.0.2.1; };", "notify-source is not legal for an IPv6 server"));
    CHECK(fails_with("server 192.0.2.1 { transfer-source 192.0.2.9 port 53; };", "takes no port"));
    CHECK(fails_with("server 192.0.2.1 { };\nserver 192.0.2.1 { };", "already exists, previous definition: line 1"));
    CHECK(fails_with("view \"v\" { server 192.0.2.0/24 { }; server 192.0.2.0/24 { }; };", "already exists, previous definition"));
    CHECK(fails_with("server 192.0.2.1 { keys nokey; };", "unknown key 'nokey'"));
    CHECK(fails_with("server 192.0.2.1 { keys nokey; };", "line 1: server '192.0.2.1'"));
    /* the same prefix in two lists (top level and a view) is not a duplicate: the view's list replaces the other */
    server_config_t c;
    char err[2048];
    CHECK(parse_cap("server 192.0.2.1 { bogus yes; };\nview \"v\" { server 192.0.2.1 { transfers 3; }; zone \"a.test\" { type master; }; };", &c, err,
                    sizeof(err)));
    free_server_config_fields(&c);
}

static void test_prefix_matching(void) {
    printf("[TEST] the most specific prefix wins; a view's statements replace the top-level ones...\n");
    server_config_t c;
    char err[4096];
    const char *conf =
        "server 192.0.2.0/24 { transfers 24; };\n"
        "server 192.0.2.128/25 { transfers 25; };\n"
        "server 192.0.0.0/16 { transfers 16; };\n"
        "server 192.0.2.77 { transfers 32; };\n"
        "server 0.0.0.0/0 { transfers 0; };\n"
        "server 2001:db8::/32 { transfers 64; };\n"
        "server 2001:db8:1::/48 { transfers 48; };\n"
        "view \"v1\" { match-clients { 127.0.0.1; }; server 192.0.2.0/24 { transfers 124; };\n"
        "  zone \"a.test\" { type master; }; };\n"
        "view \"v2\" { match-clients { any; }; zone \"b.test\" { type master; }; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    CHECK(find4(&c, "v2", "192.0.2.77")->transfers == 32);      /* /32 */
    CHECK(find4(&c, "v2", "192.0.2.200")->transfers == 25);     /* /25 beats /24 */
    CHECK(find4(&c, "v2", "192.0.2.5")->transfers == 24);       /* /24 beats /16 */
    CHECK(find4(&c, "v2", "192.0.99.5")->transfers == 16);      /* /16 beats /0 */
    CHECK(find4(&c, "v2", "203.0.113.9")->transfers == 0 && (find4(&c, "v2", "203.0.113.9")->set & SV_TRANSFERS));   /* 0.0.0.0/0 covers all */
    CHECK(find6(&c, "v2", "2001:db8:1::9")->transfers == 48);   /* /48 beats /32 */
    CHECK(find6(&c, "v2", "2001:db8:2::9")->transfers == 64);
    CHECK(find6(&c, "v2", "2001:db9::1") == NULL);              /* the v4 /0 does not cover an IPv6 address */
    /* the view with its own statement uses only its own: 192.0.2.77 is no longer covered by the /32 and falls to its /24 */
    CHECK(find4(&c, "v1", "192.0.2.77")->transfers == 124);
    CHECK(find4(&c, "v1", "203.0.113.9") == NULL);              /* neither the /0 nor anything else of the top level */
    CHECK(find6(&c, "v1", "2001:db8::1") == NULL);
    CHECK(find4(&c, NULL, "192.0.2.77")->transfers == 32 && find4(&c, "nope", "192.0.2.77")->transfers == 32 && find4(&c, "", "192.0.2.77")->transfers == 32);
    /* from text and from a socket address */
    CHECK(config_server_find_ip(&c, "v2", "192.0.2.200")->transfers == 25 && config_server_find_ip(&c, "v2", "not an address") == NULL &&
          config_server_find_ip(&c, "v2", NULL) == NULL);
    struct sockaddr_in sa4;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    inet_pton(AF_INET, "192.0.2.200", &sa4.sin_addr);
    CHECK(config_server_find_sa(&c, "v2", (struct sockaddr *)&sa4)->transfers == 25);
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::ffff:192.0.2.200", &sa6.sin6_addr);
    CHECK(config_server_find_sa(&c, "v2", (struct sockaddr *)&sa6)->transfers == 25);     /* IPv4-mapped */
    inet_pton(AF_INET6, "2001:db8:1::9", &sa6.sin6_addr);
    CHECK(config_server_find_sa(&c, "v2", (struct sockaddr *)&sa6)->transfers == 48);
    struct sockaddr sx;
    memset(&sx, 0, sizeof(sx));
    sx.sa_family = AF_UNIX;
    CHECK(config_server_find_sa(&c, "v2", &sx) == NULL && config_server_find_sa(&c, "v2", NULL) == NULL && config_server_find_sa(NULL, "v2", &sx) == NULL);
    CHECK(find4(NULL, "v2", "192.0.2.1") == NULL && server_list_find(NULL, AF_INET, (const uint8_t *)"\xc0\x00\x02\x01") == NULL);
    free_server_config_fields(&c);
    /* equal length: the earlier statement is first, and prefixes of one length cannot overlap except as the same prefix (a duplicate) */
    CHECK(parse_cap("server 192.0.2.0/25 { transfers 1; };\nserver 192.0.2.128/25 { transfers 2; };\nzone \"a.test\" { type master; };", &c, err, sizeof(err)));
    CHECK(find4(&c, NULL, "192.0.2.1")->transfers == 1 && find4(&c, NULL, "192.0.2.129")->transfers == 2);
    free_server_config_fields(&c);
}

static void test_key_precedence(void) {
    printf("[TEST] TSIG key precedence for a request to a peer...\n");
    server_stmt_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.set = SV_KEYS;
    srv.key = (char *)"srvkey";
    /* the key written on the primaries / also-notify element > the server statement's keys > the zone's tsig-key */
    CHECK(strcmp(peer_key_name("elem", &srv, "zone"), "elem") == 0);
    CHECK(strcmp(peer_key_name(NULL, &srv, "zone"), "srvkey") == 0);
    CHECK(strcmp(peer_key_name("", &srv, "zone"), "srvkey") == 0);
    CHECK(strcmp(peer_key_name(NULL, NULL, "zone"), "zone") == 0);
    CHECK(strcmp(peer_key_name(NULL, &srv, NULL), "srvkey") == 0);
    CHECK(strcmp(peer_key_name("elem", NULL, NULL), "elem") == 0);
    CHECK(peer_key_name(NULL, NULL, NULL) == NULL && peer_key_name("", NULL, "") == NULL);
    srv.set = 0;     /* a statement without `keys` is not a key */
    CHECK(strcmp(peer_key_name(NULL, &srv, "zone"), "zone") == 0);
}

static bool addr_is(const uint8_t *got, const char *ip, int fam) {
    uint8_t want[16] = {0};
    return inet_pton(fam, ip, want) == 1 && memcmp(got, want, fam == AF_INET ? 4 : 16) == 0;
}

static void test_effective_and_sources(void) {
    printf("[TEST] the server statement in the transfer / NOTIFY options and the source of a request...\n");
    server_config_t c;
    char err[4096];
    const char *conf =
        "options { transfer-source 192.0.2.1; notify-source 192.0.2.2; request-ixfr yes; provide-ixfr yes; request-expire yes; };\n"
        "server 203.0.113.1 { transfer-source 192.0.2.11; notify-source 192.0.2.12; request-ixfr no; provide-ixfr no; request-expire no; };\n"
        "server 203.0.113.2 { transfer-source *; notify-source *; };\n"
        "server 203.0.113.3 { bogus no; };\n"
        "zone \"z.test\" { type slave; primaries source 192.0.2.21 { 203.0.113.1; 203.0.113.2; 203.0.113.3; };\n"
        "  also-notify source 192.0.2.22 { 203.0.113.1; 203.0.113.2; 203.0.113.3; };\n"
        "  request-ixfr no; provide-ixfr no; };\n"
        "zone \"y.test\" { type slave; primaries { 203.0.113.1; 203.0.113.2; 203.0.113.3; }; request-ixfr yes; provide-ixfr yes; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    const zone_config_t *z = config_find_zone_any_view(&c, "z.test.");
    const zone_config_t *y = config_find_zone_any_view(&c, "y.test.");
    CHECK(z && y);
    const zone_ext_t *zx = zext(z);
    CHECK(zx->masters_count == 3);
    xfr_eff_t e;
    uint8_t out[16];
    /* 203.0.113.1: its transfer-source / notify-source beat the list's `source`; its request-ixfr etc. beat the zone's */
    const server_stmt_t *s1 = find4(&c, NULL, "203.0.113.1");
    xfr_opts_effective_peer(&c, z, NULL, s1, &e);
    CHECK(xfr_source_for(&e, &zx->masters[0], AF_INET, true, out) && addr_is(out, "192.0.2.11", AF_INET));
    CHECK(xfr_source_for(&e, &zx->also_notify[0], AF_INET, false, out) && addr_is(out, "192.0.2.12", AF_INET));
    CHECK(!e.request_ixfr && !e.provide_ixfr && !e.request_expire);
    xfr_opts_effective_peer(&c, y, NULL, s1, &e);
    CHECK(!e.request_ixfr && !e.provide_ixfr && !e.request_expire);       /* the zone says yes: the server statement still wins */
    /* 203.0.113.2: `*` in the server statement: the system chooses, the list's source is not used either */
    const server_stmt_t *s2 = find4(&c, NULL, "203.0.113.2");
    xfr_opts_effective_peer(&c, z, NULL, s2, &e);
    CHECK(!xfr_source_for(&e, &zx->masters[1], AF_INET, true, out));
    CHECK(!xfr_source_for(&e, &zx->also_notify[1], AF_INET, false, out));
    CHECK(!e.request_ixfr && !e.provide_ixfr && e.request_expire);       /* the zone's request-ixfr / provide-ixfr; options' request-expire */
    /* 203.0.113.3: a statement that writes nothing of that: the list's source, then the zone's / view's / options' as before */
    const server_stmt_t *s3 = find4(&c, NULL, "203.0.113.3");
    xfr_opts_effective_peer(&c, z, NULL, s3, &e);
    CHECK(xfr_source_for(&e, &zx->masters[2], AF_INET, true, out) && addr_is(out, "192.0.2.21", AF_INET));
    CHECK(xfr_source_for(&e, &zx->also_notify[2], AF_INET, false, out) && addr_is(out, "192.0.2.22", AF_INET));
    xfr_opts_effective_peer(&c, y, NULL, s3, &e);
    CHECK(xfr_source_for(&e, &zext(y)->masters[2], AF_INET, true, out) && addr_is(out, "192.0.2.1", AF_INET));     /* options' transfer-source */
    CHECK(xfr_source_for(&e, NULL, AF_INET, false, out) && addr_is(out, "192.0.2.2", AF_INET));
    /* no server statement: the same as xfr_opts_effective() */
    xfr_eff_t e0, e1;
    xfr_opts_effective(&c, z, NULL, &e0);
    xfr_opts_effective_peer(&c, z, NULL, NULL, &e1);
    CHECK(e0.request_ixfr == e1.request_ixfr && e0.provide_ixfr == e1.provide_ixfr && e0.request_expire == e1.request_expire);
    CHECK(xfr_source_for(&e1, &zx->masters[0], AF_INET, true, out) && addr_is(out, "192.0.2.21", AF_INET));
    /* IPv6: the -v6 slot of a v6 server */
    free_server_config_fields(&c);
    CHECK(parse_cap("server 2001:db8::1 { transfer-source-v6 2001:db8::11; notify-source-v6 2001:db8::12; };\n"
                    "zone \"z.test\" { type slave; primaries { 2001:db8::1; }; also-notify { 2001:db8::1; }; };\n", &c, err, sizeof(err)));
    z = config_find_zone_any_view(&c, "z.test.");
    xfr_opts_effective_peer(&c, z, NULL, find6(&c, NULL, "2001:db8::1"), &e);
    CHECK(xfr_source_for(&e, &zext(z)->masters[0], AF_INET6, true, out) && addr_is(out, "2001:db8::11", AF_INET6));
    CHECK(xfr_source_for(&e, &zext(z)->also_notify[0], AF_INET6, false, out) && addr_is(out, "2001:db8::12", AF_INET6));
    CHECK(!xfr_source_for(&e, NULL, AF_INET, true, out));
    free_server_config_fields(&c);
}

static void test_server_sources_registry(void) {
    printf("[TEST] the source addresses of server statements are in the source registry...\n");
    server_config_t c;
    char err[4096];
    CHECK(parse_cap("server 203.0.113.1 { transfer-source 192.0.2.11; notify-source 192.0.2.12; };\n"
                    "view \"v\" { server 203.0.113.2 { transfer-source 192.0.2.13; notify-source 192.0.2.12; };\n"
                    "  zone \"a.test\" { type master; }; };\n", &c, err, sizeof(err)));
    CHECK(c.xfr_source_count == 3);
    int found = 0;
    for (int i = 0; i < c.xfr_source_count; i++) {
        const xfr_source_t *s = &c.xfr_sources[i];
        if (strcmp(s->text, "192.0.2.11") == 0 && s->xfer && !s->notify) found++;
        if (strcmp(s->text, "192.0.2.12") == 0 && s->notify && !s->xfer) found++;
        if (strcmp(s->text, "192.0.2.13") == 0 && s->xfer && !s->notify) found++;
    }
    CHECK(found == 3);
    CHECK(strstr(c.xfr_sources[0].loc, "line 1") != NULL);
    free_server_config_fields(&c);
}

static void test_view_keys(void) {
    printf("[TEST] key { } in view { }...\n");
    server_config_t c;
    char err[4096];
    const char *conf =
        KEYDEF("g", KEYA)
        "view \"v1\" { match-clients { 127.0.0.1; };\n"
        "  key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; };\n"
        "  key \"only1\" { algorithm hmac-sha512; secret \"" KEYA "\"; };\n"
        "  server 192.0.2.1 { keys k; };\n"
        "  zone \"a.test\" { type slave; primaries { 192.0.2.1 key k; }; allow-transfer { key k; key g; }; tsig-key only1; };\n"
        "};\n"
        "view \"v2\" { match-clients { any; };\n"
        "  key \"k\" { algorithm hmac-sha256; secret \"" KEYB "\"; };\n"
        "  zone \"b.test\" { type master; allow-transfer { key k; }; allow-update { key k; }; };\n"
        "};\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    tsig_key_t *a1 = find_tsig_key_in_view(&c, "v1", "k");
    tsig_key_t *a2 = find_tsig_key_in_view(&c, "v2", "k");
    CHECK(a1 && a2 && a1 != a2 && memcmp(a1->secret_decoded, a2->secret_decoded, 8) != 0);       /* two views, two different keys of one name */
    CHECK(find_tsig_key_in_view(&c, NULL, "k") == NULL && find_tsig_key_in_view(&c, "", "k") == NULL && find_tsig_key_in_view(&c, "nope", "k") == NULL);
    CHECK(find_tsig_key_in_view(&c, "v1", "K.") == a1);                           /* a DNS name: case and the final dot do not matter */
    CHECK(find_tsig_key_in_view(&c, "v1", "only1") != NULL && find_tsig_key_in_view(&c, "v2", "only1") == NULL);
    CHECK(find_tsig_key_in_view(&c, "v1", "g") == find_tsig_key_by_name(&c, "g") && find_tsig_key_in_view(&c, "v2", "g") != NULL);   /* a global key is in every view */
    CHECK(find_tsig_key_by_name(&c, "k") == NULL);                                /* a view's key is not global */
    CHECK(find_tsig_key_in_view(&c, "v1", NULL) == NULL && find_tsig_key_in_view(&c, "v1", "") == NULL && find_tsig_key_in_view(NULL, "v1", "k") == NULL);
    free_server_config_fields(&c);

    /* errors */
    CHECK(fails_with(KEYDEF("k", KEYA) "view \"v\" { key \"k\" { algorithm hmac-sha256; secret \"" KEYB "\"; }; };",
                     "key 'k' already exists as a top-level key"));
    CHECK(fails_with("view \"v\" { key \"k\" { algorithm hmac-sha256; secret \"" KEYB "\"; }; key \"K\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; };",
                     "duplicate TSIG key 'K' defined"));
    CHECK(fails_with("view \"v\" { key \"k\" { algorithm hmac-sha256; }; };", "'secret' is missing"));
    CHECK(fails_with("view \"v\" { key \"k\" { secret \"" KEYA "\"; }; };", "'algorithm' is missing"));
    CHECK(fails_with("view \"v\" { key \"k\" { algorithm hmac-sha256; secret \"!!!\"; }; };", "not valid base64"));
    CHECK(fails_with("view \"v\" { key \"k\" { algorithm no-such-alg; secret \"" KEYA "\"; }; };", "Unsupported TSIG algorithm"));
    CHECK(fails_with("view \"v\" { key \"k\" { algorithm hmac-sha256; algorithm hmac-sha256; secret \"" KEYA "\"; }; };", "'algorithm' is given twice"));
    CHECK(fails_with("view \"v\" { key \"k\" { frob 1; }; };", "unknown option 'frob'"));
    /* a name used in a view that only another view has */
    CHECK(fails_with("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                     "view \"v2\" { match-clients { any; }; zone \"b.test\" { type master; tsig-key k; }; };", "Zone 'b.test.': tsig-key 'k' is not defined"));
    CHECK(fails_with("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                     "view \"v2\" { match-clients { any; }; zone \"b.test\" { type master; allow-transfer { key k; }; }; };", "key 'k'"));
    CHECK(fails_with("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                     "view \"v2\" { match-clients { any; }; zone \"b.test\" { type master; allow-update { key k; }; }; };", "key 'k'"));
    CHECK(fails_with("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                     "view \"v2\" { match-clients { any; }; zone \"b.test\" { type slave; primaries { 192.0.2.1 key k; }; }; };", "key 'k' is not defined"));
    CHECK(fails_with("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                     "view \"v2\" { match-clients { any; }; also-notify { 192.0.2.1 key k; }; zone \"b.test\" { type master; }; };", "key 'k' is not defined"));
    /* a top-level server statement is used by a view that has none of its own: the key must be there too */
    CHECK(fails_with("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                     "view \"v2\" { match-clients { any; }; zone \"b.test\" { type master; }; };\nserver 192.0.2.1 { keys k; };",
                     "unknown key 'k' (in view 'v2')"));
    /* ... unless the view has statements of its own (they replace the top-level ones) */
    CHECK(parse_cap("view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
                    "view \"v2\" { match-clients { any; }; server 192.0.2.9 { }; zone \"b.test\" { type master; }; };\nserver 192.0.2.1 { keys g; };\n" KEYDEF("g", KEYA),
                    &c, err, sizeof(err)));
    free_server_config_fields(&c);
    /* without views: the default view sees the global keys only */
    CHECK(fails_with("server 192.0.2.1 { keys k; };", "unknown key 'k'"));
    CHECK(parse_cap(KEYDEF("k", KEYA) "server 192.0.2.1 { keys k; };", &c, err, sizeof(err)));
    free_server_config_fields(&c);
}

/* A query for example.test. A signed with the key (RFC 8945 §4.2: hmac-sha256), as a client would send it */
static size_t signed_query(uint8_t *buf, size_t cap, tsig_key_t *key) {   /* key NULL: left unsigned */
    static const uint8_t q[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1};
    memcpy(buf, q, sizeof(q));
    size_t len = sizeof(q);
    if (!key) return len;
    uint8_t mac[64];
    size_t mac_len = 0;
    if (tsig_sign_packet(buf, &len, cap, key, 0, mac, &mac_len, NULL, 0, false) != 0) return 0;
    return len;
}

static void test_tsig_check_view(void) {
    printf("[TEST] a request is verified with the keys of the view it belongs to...\n");
    server_config_t c;
    char err[4096];
    const char *conf =
        KEYDEF("g", KEYA)
        "view \"v1\" { match-clients { 127.0.0.1; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYA "\"; }; zone \"a.test\" { type master; }; };\n"
        "view \"v2\" { match-clients { any; }; key \"k\" { algorithm hmac-sha256; secret \"" KEYB "\"; }; zone \"b.test\" { type master; }; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    tsig_key_t *k1 = find_tsig_key_in_view(&c, "v1", "k");
    tsig_key_t *k2 = find_tsig_key_in_view(&c, "v2", "k");
    tsig_key_t *g = find_tsig_key_by_name(&c, "g");
    CHECK(k1 && k2 && g);
    uint8_t pkt[1024];
    tsig_request_t t;
    size_t n = signed_query(pkt, sizeof(pkt), k1);
    CHECK(n > 0);
    tsig_check_request(&c, "v1", pkt, n, "127.0.0.1", &t);
    CHECK(t.status == TSIG_REQ_VALID && t.key == k1);
    tsig_check_request(&c, "v2", pkt, n, "127.0.0.1", &t);        /* the same name, another secret: BADSIG, not accepted by luck */
    CHECK(t.status == TSIG_REQ_ERROR && t.error == 16);
    tsig_check_request(&c, NULL, pkt, n, "127.0.0.1", &t);        /* no view: only the global keys; the name is unknown */
    CHECK(t.status == TSIG_REQ_ERROR && t.error == 17);
    tsig_check_request(&c, "nope", pkt, n, "127.0.0.1", &t);
    CHECK(t.status == TSIG_REQ_ERROR && t.error == 17);
    n = signed_query(pkt, sizeof(pkt), k2);
    tsig_check_request(&c, "v2", pkt, n, "192.0.2.1", &t);
    CHECK(t.status == TSIG_REQ_VALID && t.key == k2);
    tsig_check_request(&c, "v1", pkt, n, "192.0.2.1", &t);
    CHECK(t.status == TSIG_REQ_ERROR && t.error == 16);
    n = signed_query(pkt, sizeof(pkt), g);                        /* a global key is valid in every view */
    tsig_check_request(&c, "v1", pkt, n, "192.0.2.1", &t);
    CHECK(t.status == TSIG_REQ_VALID && t.key == g);
    tsig_check_request(&c, "v2", pkt, n, "192.0.2.1", &t);
    CHECK(t.status == TSIG_REQ_VALID && t.key == g);
    tsig_check_request(&c, NULL, pkt, n, "192.0.2.1", &t);
    CHECK(t.status == TSIG_REQ_VALID && t.key == g);
    n = signed_query(pkt, sizeof(pkt), NULL);                     /* no additional section: no TSIG */
    tsig_check_request(&c, "v1", pkt, n, "192.0.2.1", &t);
    CHECK(t.status == TSIG_REQ_NONE);
    free_server_config_fields(&c);
}

static void test_nested_ports(void) {
    printf("[TEST] a nested primaries list without a port takes the port of the enclosing list...\n");
    server_config_t c;
    char err[4096];
    const char *conf =
        "primaries inner { 192.0.2.1; 192.0.2.2 port 1000; };\n"
        "primaries inner6000 port 6000 { 192.0.2.3; };\n"
        "primaries deep { inner; };\n"
        "primaries outer5353 port 5353 { inner; inner6000; 192.0.2.4; 192.0.2.5 port 2000; deep; };\n"
        "primaries outer_noport { inner; 192.0.2.6; };\n"
        "primaries source_in source 192.0.2.99 port 4000 { 192.0.2.7; };\n"
        "zone \"a.test\" { type slave; primaries { outer5353; }; };\n"
        "zone \"b.test\" { type slave; primaries { inner; }; };\n"
        "zone \"c.test\" { type slave; primaries port 7000 { outer_noport; 192.0.2.8; }; };\n"
        "zone \"d.test\" { type slave; primaries port 7000 { outer5353; }; };\n"
        "zone \"e.test\" { type slave; primaries port 7000 { source_in; }; };\n"
        "zone \"f.test\" { type master; also-notify port 8000 { inner; inner6000; }; };\n"
        "zone \"g.test\" { type master; also-notify { inner; }; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    const zone_config_t *z;
    z = config_find_zone_any_view(&c, "a.test.");
    CHECK(z && zext(z)->masters_count == 7);
    if (z && zext(z)->masters_count == 7) {
        const notify_target_t *m = zext(z)->masters;
        CHECK(strcmp(m[0].ip, "192.0.2.1") == 0 && m[0].port == 5353);     /* inner has no port: the outer 5353 */
        CHECK(strcmp(m[1].ip, "192.0.2.2") == 0 && m[1].port == 1000);     /* its own port */
        CHECK(strcmp(m[2].ip, "192.0.2.3") == 0 && m[2].port == 6000);     /* the inner list's own port beats the enclosing list's */
        CHECK(strcmp(m[3].ip, "192.0.2.4") == 0 && m[3].port == 5353);
        CHECK(strcmp(m[4].ip, "192.0.2.5") == 0 && m[4].port == 2000);
        CHECK(strcmp(m[5].ip, "192.0.2.1") == 0 && m[5].port == 5353);     /* deep -> inner: two levels, still the outermost port */
        CHECK(strcmp(m[6].ip, "192.0.2.2") == 0 && m[6].port == 1000);
    }
    z = config_find_zone_any_view(&c, "b.test.");
    CHECK(z && zext(z)->masters_count == 2 && zext(z)->masters[0].port == 53 && zext(z)->masters[1].port == 1000);        /* no port anywhere: 53 */
    z = config_find_zone_any_view(&c, "c.test.");
    CHECK(z && zext(z)->masters_count == 4);
    if (z && zext(z)->masters_count == 4) {
        const notify_target_t *m = zext(z)->masters;
        CHECK(m[0].port == 7000 && m[1].port == 1000 && m[2].port == 7000 && m[3].port == 7000);   /* the zone statement's port reaches the lists */
    }
    z = config_find_zone_any_view(&c, "d.test.");
    CHECK(z && zext(z)->masters_count == 7);
    if (z && zext(z)->masters_count == 7) {
        const notify_target_t *m = zext(z)->masters;
        CHECK(m[0].port == 5353 && m[2].port == 6000 && m[3].port == 5353);   /* outer5353 has a port: the zone statement's 7000 is not used */
    }
    z = config_find_zone_any_view(&c, "e.test.");
    CHECK(z && zext(z)->masters_count == 1 && zext(z)->masters[0].port == 4000);    /* the list's port; its source is the list's too */
    if (z && zext(z)->masters_count == 1) {
        uint8_t want[4];
        CHECK(v4("192.0.2.99", want) && zext(z)->masters[0].src_set[0] && memcmp(zext(z)->masters[0].src[0], want, 4) == 0);
    }
    z = config_find_zone_any_view(&c, "f.test.");
    CHECK(z && zext(z)->also_notify_count == 3 && zext(z)->also_notify[0].port == 8000 && zext(z)->also_notify[1].port == 1000 &&
          zext(z)->also_notify[2].port == 6000);
    z = config_find_zone_any_view(&c, "g.test.");
    CHECK(z && zext(z)->also_notify_count == 2 && zext(z)->also_notify[0].port == 53);
    free_server_config_fields(&c);
}

int main(void) {
    test_parse_options();
    test_clamps();
    test_parse_errors();
    test_prefix_matching();
    test_key_precedence();
    test_effective_and_sources();
    test_server_sources_registry();
    test_view_keys();
    test_tsig_check_view();
    test_nested_ports();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("test_server_stmt: FAILED\n");
        return 1;
    }
    printf("test_server_stmt: all passed\n");
    return 0;
}

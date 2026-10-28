/*
 * test_acl_match.c - BIND address match lists (BIND 9.20 ARM "Address Match Lists", "acl Block Definition and Usage"):
 * parsing of allow-query / allow-query-on / allow-transfer / allow-update / allow-notify and acl blocks, first-match evaluation
 * (negation, key, nested lists, named acls, localhost / localnets), inheritance zone > view > options, and the ACL decisions of
 * dns_tsig_acl.c that use them.
 *
 * Expectations come from the ARM text ("a non-negated match allows access and a negated match denies access. If there is no match,
 * access is denied", "Order of insertion is significant") and from BIND's lib/dns/acl.c (a negative match inside a nested list is
 * "no match" for the element that holds the list), worked out by hand for each case -- not from running the code and pasting its
 * answers.  Addresses are documentation addresses (RFC 5737, RFC 3849).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../dns_config_parser.h"
#include "../dns_tsig_acl.h"

/* dns_config_parser.c calls this through the privileged-directory cache in the real server. */
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

#define KEYS \
    "key \"k1\" { algorithm hmac-sha256; secret \"c2VjcmV0LW9uZS1mb3ItdGVzdA==\"; };" \
    "key \"k2\" { algorithm hmac-sha256; secret \"c2VjcmV0LXR3by1mb3ItdGVzdA==\"; };"

static bool parse_cfg(const char *text, server_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    return parse_named_conf(text, cfg) == 0;
}

/* a parse that must fail (the partially built configuration has been freed by the parser) */
static bool rejects(const char *text) {
    server_config_t cfg;
    if (parse_cfg(text, &cfg)) {
        free_server_config_fields(&cfg);
        return false;
    }
    return true;
}

/* evaluate the list of "options { allow-query { LIST }; }" for (ip, key): > 0 allowed, < 0 negated match, 0 nothing matched */
static int qmatch(const char *prelude, const char *list, const char *ip, const char *key) {
    char txt[2048];
    server_config_t cfg;
    snprintf(txt, sizeof(txt), KEYS "%s options { allow-query { %s }; };", prelude, list);
    if (!parse_cfg(txt, &cfg)) {
        printf("  [FAIL] does not parse: %s\n", txt);
        g_failed++;
        g_checks++;
        return 99;
    }
    const aml_t *l = config_acl_for(&cfg, NULL, NULL, AML_ACL_QUERY);
    aml_subject_t s;
    uint8_t b[16];
    int r = 99;
    if (l && aml_subject_from_ip(&s, b, ip, key)) r = aml_match(l, &s);
    free_server_config_fields(&cfg);
    return r;
}

#define M(prelude, list, ip, key, want) do { \
    int got_ = qmatch(prelude, list, ip, key); \
    g_checks++; \
    if (got_ != (want)) { g_failed++; printf("  [FAIL] %s:%d: { %s } for %s key %s: got %d want %d\n", __FILE__, __LINE__, list, ip, \
                                              (key) ? (key) : "-", got_, (want)); } \
} while (0)

static void test_first_match(void) {
    printf("[TEST] first match, negation, any / none\n");
    M("", "192.0.2.0/24;", "192.0.2.5", NULL, 1);
    M("", "192.0.2.0/24;", "198.51.100.1", NULL, 0);
    M("", "192.0.2.0/24;", "2001:db8::1", NULL, 0);
    M("", "!192.0.2.5; 192.0.2.0/24;", "192.0.2.5", NULL, -1);      /* the negated host comes first */
    M("", "!192.0.2.5; 192.0.2.0/24;", "192.0.2.6", NULL, 1);
    M("", "192.0.2.0/24; !192.0.2.5;", "192.0.2.5", NULL, 1);       /* "Order of insertion is significant" */
    M("", "! 192.0.2.5; any;", "192.0.2.5", NULL, -1);              /* "!" as a word of its own */
    M("", "!192.0.2.5; any;", "203.0.113.9", NULL, 1);
    M("", "any;", "203.0.113.9", NULL, 1);
    M("", "none;", "203.0.113.9", NULL, 0);
    M("", "", "203.0.113.9", NULL, 0);                              /* an empty list matches nobody */
    M("", "!any;", "203.0.113.9", NULL, -1);
    M("", "ANY;", "203.0.113.9", NULL, 1);                          /* the built-in names are not case sensitive */
    M("", "2001:db8::/32;", "2001:db8:ffff::1", NULL, 1);
    M("", "2001:db8::/32;", "2001:db9::1", NULL, 0);
    M("", "192.0.2.1;", "192.0.2.1", NULL, 1);                      /* a host: /32 */
    M("", "192.0.2.1;", "192.0.2.2", NULL, 0);
    M("", "0.0.0.0/0;", "198.51.100.1", NULL, 1);
    M("", "0.0.0.0/0;", "2001:db8::1", NULL, 0);                    /* a v4 prefix never matches a v6 client */
}

static void test_keys(void) {
    printf("[TEST] key elements\n");
    M("", "key k1;", "203.0.113.9", "k1", 1);                       /* signed with k1, from anywhere */
    M("", "key k1;", "203.0.113.9", NULL, 0);
    M("", "key k1;", "203.0.113.9", "k2", 0);
    M("", "key \"k1\";", "203.0.113.9", "K1.", 1);                  /* key names are DNS names (RFC 4343): case and the final dot do not matter */
    M("", "!key k1; any;", "203.0.113.9", "k1", -1);
    M("", "!key k1; any;", "203.0.113.9", "k2", 1);
    M("", "!key k1; any;", "203.0.113.9", NULL, 1);
    M("", "192.0.2.1; key k1;", "192.0.2.1", NULL, 1);              /* address OR key */
    M("", "192.0.2.1; key k1;", "198.51.100.1", "k1", 1);
    M("", "192.0.2.1; key k1;", "198.51.100.1", NULL, 0);
    M("", "key k1; !192.0.2.1; any;", "192.0.2.1", "k1", 1);        /* the key comes first */
    M("", "!192.0.2.1; key k1; any;", "192.0.2.1", "k1", -1);       /* the address comes first */
}

static void test_nested_and_named(void) {
    printf("[TEST] nested lists, acl blocks\n");
    M("", "{ 10.0.0.0/8; 192.0.2.0/24; };", "192.0.2.7", NULL, 1);
    M("", "{ 10.0.0.0/8; 192.0.2.0/24; };", "172.16.0.1", NULL, 0);
    M("", "!{ 192.0.2.5; }; any;", "192.0.2.5", NULL, -1);
    M("", "!{ 192.0.2.5; }; any;", "192.0.2.6", NULL, 1);
    /* the idiom for "this address AND this key": !{ !A; any; }; key K; */
    M("", "!{ !192.0.2.1; any; }; key k1;", "192.0.2.1", "k1", 1);
    M("", "!{ !192.0.2.1; any; }; key k1;", "192.0.2.1", NULL, 0);
    M("", "!{ !192.0.2.1; any; }; key k1;", "192.0.2.2", "k1", -1);
    M("", "!{ !192.0.2.1; any; }; key k1;", "192.0.2.2", NULL, -1);
    /* a negative match inside a nested list is "no match" for the element that holds it: the next element is tried */
    M("", "{ !192.0.2.5; 192.0.2.0/24; }; 198.51.100.0/24;", "192.0.2.5", NULL, 0);
    M("", "{ !192.0.2.5; 192.0.2.0/24; }; any;", "192.0.2.5", NULL, 1);
    /* acl blocks, also used before they are written */
    M("acl internal { 10.0.0.0/8; trusted; };" "acl trusted { 192.0.2.0/24; };", "internal;", "192.0.2.9", NULL, 1);
    M("acl internal { 10.0.0.0/8; trusted; };" "acl trusted { 192.0.2.0/24; };", "internal;", "10.1.1.1", NULL, 1);
    M("acl internal { 10.0.0.0/8; trusted; };" "acl trusted { 192.0.2.0/24; };", "internal;", "198.51.100.1", NULL, 0);
    M("acl x { !10.0.0.5; 10.0.0.0/8; };", "!x; any;", "10.0.0.6", NULL, -1);   /* x matches positively: "!x" denies */
    M("acl x { !10.0.0.5; 10.0.0.0/8; };", "!x; any;", "10.0.0.5", NULL, 1);    /* x matches negatively = no match, so "any" decides */
    M("acl x { key k1; };", "x;", "203.0.113.9", "k1", 1);                         /* a key inside an acl block */
    M("acl Mixed { 192.0.2.1; };", "mixed;", "192.0.2.1", NULL, 1);                /* acl names are not case sensitive */
}

static void test_localhost_localnets(void) {
    printf("[TEST] localhost, localnets\n");
    aml_iface_t v[5];
    memset(v, 0, sizeof(v));
    v[0].family = AF_INET;  inet_pton(AF_INET, "192.0.2.10", v[0].addr);       inet_pton(AF_INET, "255.255.255.0", v[0].mask);
    v[1].family = AF_INET;  inet_pton(AF_INET, "10.1.2.3", v[1].addr);         inet_pton(AF_INET, "255.0.0.0", v[1].mask);
    v[2].family = AF_INET6; inet_pton(AF_INET6, "::1", v[2].addr);             memset(v[2].mask, 0xff, 16);
    v[3].family = AF_INET6; inet_pton(AF_INET6, "2001:db8:1::5", v[3].addr);   inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", v[3].mask);
    v[4].family = AF_INET;  inet_pton(AF_INET, "127.0.0.1", v[4].addr);        inet_pton(AF_INET, "255.0.0.0", v[4].mask);
    aml_set_interfaces(v, 5);
    M("", "localhost;", "192.0.2.10", NULL, 1);
    M("", "localhost;", "192.0.2.11", NULL, 0);                      /* localhost = the addresses of the interfaces, not their networks */
    M("", "localhost;", "10.1.2.3", NULL, 1);
    M("", "localhost;", "::1", NULL, 1);
    M("", "localhost;", "2001:db8:1::5", NULL, 1);
    M("", "localhost;", "2001:db8:1::6", NULL, 0);
    M("", "localhost;", "127.0.0.1", NULL, 1);
    M("", "localnets;", "192.0.2.99", NULL, 1);                      /* localnets = any host on a network the system has an interface on */
    M("", "localnets;", "192.0.3.1", NULL, 0);
    M("", "localnets;", "10.200.0.1", NULL, 1);
    M("", "localnets;", "2001:db8:1::99", NULL, 1);
    M("", "localnets;", "2001:db8:2::1", NULL, 0);
    M("", "localnets;", "198.51.100.1", NULL, 0);
    M("", "!localhost; localnets;", "192.0.2.10", NULL, -1);
    M("", "!localhost; localnets;", "192.0.2.11", NULL, 1);
    M("acl lan { localnets; };", "lan;", "10.9.9.9", NULL, 1);       /* inside an acl block */
    M("", "LocalHost;", "192.0.2.10", NULL, 1);
    /* the flat lists (the settings text sent to secondaries, match-clients, ecs-trusted-resolvers) get the addresses and networks */
    {
        server_config_t cfg;
        CHECK(parse_cfg("view \"v\" { match-clients { localnets; }; zone \"a.test\" { type master; file \"z\"; allow-transfer { localhost; }; }; };", &cfg));
        zone_config_t *z = view_find_zone_config(cfg.views, "a.test");
        CHECK(z && zext(z)->allow_transfer_count == 5);
        CHECK(z && zext(z)->allow_transfer_count == 5 && strcmp(zext(z)->allow_transfer[0], "192.0.2.10/32") == 0);
        CHECK(z && zext(z)->allow_transfer_count == 5 && strcmp(zext(z)->allow_transfer[3], "2001:db8:1::5/128") == 0);
        CHECK(cfg.views->match_clients_count == 5);
        CHECK(cfg.views->match_clients_count == 5 && strcmp(cfg.views->match_clients[0], "192.0.2.10/24") == 0);
        CHECK(cfg.views->match_clients_count == 5 && strcmp(cfg.views->match_clients[3], "2001:db8:1::5/64") == 0);
        free_server_config_fields(&cfg);
    }
    /* an address the server does not know (allow-query-on without the local address): only `any` matches */
    {
        aml_subject_t s = { 0, NULL, NULL };
        server_config_t cfg;
        CHECK(parse_cfg("options { allow-query-on { 192.0.2.10; localhost; }; };", &cfg));
        CHECK(aml_match(config_acl_for(&cfg, NULL, NULL, AML_ACL_QUERY_ON), &s) == 0);
        free_server_config_fields(&cfg);
        CHECK(parse_cfg("options { allow-query-on { any; }; };", &cfg));
        CHECK(aml_match(config_acl_for(&cfg, NULL, NULL, AML_ACL_QUERY_ON), &s) == 1);
        free_server_config_fields(&cfg);
    }
    aml_set_interfaces(NULL, 0);
}

static void test_errors(void) {
    printf("[TEST] errors\n");
    CHECK(rejects("options { allow-query { nosuchacl; }; };"));
    CHECK(rejects("options { allow-query { key nokey; }; };"));
    CHECK(rejects("options { allow-query { 192.0.2.300; }; };"));
    CHECK(rejects("options { allow-query { 192.0.2.1 }; };"));            /* no ';' */
    CHECK(rejects("options { allow-query { 192.0.2.0/33; }; };"));
    CHECK(rejects("options { allow-query { key; }; };"));
    CHECK(rejects("options { allow-query { !; }; };"));
    CHECK(rejects("options { allow-query 192.0.2.1; };"));                 /* no braces */
    CHECK(rejects("options { allow-query { any; }; allow-query { none; }; };"));   /* written twice in the same block */
    CHECK(rejects("options { allow-transfer port 53 { any; }; };"));      /* qualifiers the server cannot honour */
    CHECK(rejects("options { allow-transfer transport tls { any; }; };"));
    CHECK(rejects("acl a { b; }; acl b { a; }; options { allow-query { a; }; };"));
    CHECK(rejects("acl a { a; }; options { allow-query { a; }; };"));
    CHECK(rejects("acl localnets { 192.0.2.1; };"));
    CHECK(rejects("acl a { key nokey; }; options { allow-query { a; }; };"));
    CHECK(rejects(KEYS "zone \"a.test\" { type master; file \"z\"; allow-query { 1.2.3.4; allow-update { any; }; };"));
    CHECK(rejects(KEYS "zone \"a.test\" { type master; file \"z\"; allow-transfer { !key k1; any; }; transfer-acl-match all; };"));
    CHECK(rejects(KEYS "zone \"a.test\" { type master; file \"z\"; allow-update { !key k1; any; }; update-acl-match any; };"));
    {   /* ... but the same lists are fine in BIND's own (first match) mode */
        server_config_t cfg;
        CHECK(parse_cfg(KEYS "zone \"a.test\" { type master; file \"z\"; allow-transfer { !key k1; any; }; };", &cfg));
        free_server_config_fields(&cfg);
    }
    /* nested more than the parser allows */
    CHECK(rejects("options { allow-query { { { { { { { { { { any; }; }; }; }; }; }; }; }; }; }; };"));
    /* a nested list that is acceptable */
    {
        server_config_t cfg;
        CHECK(parse_cfg("options { allow-query { { { { any; }; }; }; }; };", &cfg));
        free_server_config_fields(&cfg);
    }
    /* match-clients: the same grammar, address only */
    CHECK(rejects(KEYS "view \"v\" { match-clients { key k1; }; };"));
    CHECK(rejects(KEYS "view \"v\" { match-clients { 192.0.2.1; { key k1; }; }; };"));
    CHECK(rejects("view \"v\" { match-clients { nosuch; }; };"));
    CHECK(rejects("view \"v\" { match-clients { any; }; match-clients { none; }; };"));
    {
        server_config_t cfg;
        CHECK(parse_cfg("acl lan { 10.0.0.0/8; }; view \"v\" { match-clients { !192.0.2.5; { 192.0.2.0/24; lan; }; !{ 198.51.100.0/24; }; }; };", &cfg));
        CHECK(cfg.views->match_clients_count == 4 && strcmp(cfg.views->match_clients[0], "!192.0.2.5") == 0 &&
              strcmp(cfg.views->match_clients[1], "192.0.2.0/24") == 0 && strcmp(cfg.views->match_clients[2], "10.0.0.0/8") == 0 &&
              strcmp(cfg.views->match_clients[3], "!198.51.100.0/24") == 0);
        CHECK(check_acl("192.0.2.9", cfg.views->match_clients, cfg.views->match_clients_count));
        CHECK(!check_acl("192.0.2.5", cfg.views->match_clients, cfg.views->match_clients_count));
        free_server_config_fields(&cfg);
    }
}

static bool tr_allowed(const server_config_t *cfg, const char *zone, const char *view, const char *ip, const char *key) {
    const zone_config_t *z = config_find_zone_any_view(cfg, zone);
    return z && zone_transfer_acl_allows_in_view(cfg, z, view, ip, key);
}
static bool up_allowed(const server_config_t *cfg, const char *zone, const char *view, const char *ip, const char *key) {
    const zone_config_t *z = config_find_zone_any_view(cfg, zone);
    return z && zone_update_acl_allows_in_view(cfg, z, view, ip, key);
}

static void test_inheritance(void) {
    printf("[TEST] zone > view > options\n");
    server_config_t cfg;
    CHECK(parse_cfg(KEYS
        "options { allow-query { 192.0.2.1; }; allow-query-on { 192.0.2.53; }; allow-transfer { 192.0.2.2; }; allow-update { 192.0.2.3; }; allow-notify { 192.0.2.4; }; };"
        "view \"v1\" { match-clients { 127.0.0.0/8; }; allow-query { 192.0.2.11; }; allow-transfer { 192.0.2.12; };"
        "  zone \"a.test\" { type master; file \"z\"; };"
        "  zone \"b.test\" { type master; file \"z\"; allow-query { none; }; allow-transfer { }; allow-update { key k1; }; };"
        "};"
        "view \"v2\" { match-clients { any; };"
        "  zone \"c.test\" { type slave; file \"z\"; masters { 192.0.2.99; }; };"
        "  zone \"d.test\" { type slave; file \"z\"; masters { 192.0.2.99; }; allow-notify { 192.0.2.44; }; };"
        "};", &cfg));
    const view_config_t *v1 = cfg.views, *v2 = cfg.views->next;
    CHECK(strcmp(v1->name, "v1") == 0 && v2);
    const zone_config_t *a = view_find_zone_config(v1, "a.test"), *b = view_find_zone_config(v1, "b.test");
    const zone_config_t *c = view_find_zone_config(v2, "c.test"), *d = view_find_zone_config(v2, "d.test");
    CHECK(a && b && c && d);
    CHECK(config_acl_for(&cfg, a, "v1", AML_ACL_QUERY) == v1->acl.query);          /* the view's */
    CHECK(config_acl_for(&cfg, b, "v1", AML_ACL_QUERY) == zext(b)->acl.query);     /* the zone's */
    CHECK(config_acl_for(&cfg, c, "v2", AML_ACL_QUERY) == cfg.acl.query);          /* options' */
    CHECK(config_acl_for(&cfg, a, "v1", AML_ACL_QUERY_ON) == cfg.acl.query_on);
    CHECK(config_acl_for(&cfg, c, "v2", AML_ACL_NOTIFY) == cfg.acl.notify);
    CHECK(config_acl_for(&cfg, d, "v2", AML_ACL_NOTIFY) == zext(d)->acl.notify);
    CHECK(config_acl_for(&cfg, a, "nope", AML_ACL_QUERY) == cfg.acl.query);        /* an unknown view name: options' */
    CHECK(config_acl_for(&cfg, a, NULL, AML_ACL_QUERY) == cfg.acl.query);
    CHECK(cfg.acl_query_active);

    /* allow-query + allow-query-on (both must allow), key, local address */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    inet_pton(AF_INET, "192.0.2.53", &local.sin_addr);
    CHECK(query_acl_permits(&cfg, c, "v2", "192.0.2.1", NULL, &local));
    CHECK(!query_acl_permits(&cfg, c, "v2", "192.0.2.2", NULL, &local));           /* allow-query refuses */
    CHECK(!query_acl_permits(&cfg, c, "v2", "192.0.2.1", NULL, NULL));             /* local address unknown: allow-query-on refuses */
    inet_pton(AF_INET, "192.0.2.54", &local.sin_addr);
    CHECK(!query_acl_permits(&cfg, c, "v2", "192.0.2.1", NULL, &local));           /* allow-query-on refuses */
    /* a.test: the view's allow-query (192.0.2.11), options' allow-query-on (192.0.2.53, which the view does not override) */
    inet_pton(AF_INET, "192.0.2.53", &local.sin_addr);
    CHECK(query_acl_permits(&cfg, a, "v1", "192.0.2.11", NULL, &local));
    CHECK(!query_acl_permits(&cfg, a, "v1", "192.0.2.1", NULL, &local));            /* the view's list replaces options' */
    CHECK(!query_acl_permits(&cfg, a, "v1", "192.0.2.11", NULL, NULL));
    free_server_config_fields(&cfg);

    /* options' allow-query-on applies to a view that does not write one; with no local address it refuses */
    CHECK(parse_cfg("options { allow-query-on { 192.0.2.53; }; }; view \"v\" { match-clients { any; }; allow-query { any; };"
                    " zone \"a.test\" { type master; file \"z\"; }; };", &cfg));
    {
        const zone_config_t *z = view_find_zone_config(cfg.views, "a.test");
        CHECK(!query_acl_permits(&cfg, z, "v", "192.0.2.1", NULL, NULL));
    }
    free_server_config_fields(&cfg);

    /* transfers */
    CHECK(parse_cfg(KEYS
        "options { allow-transfer { 192.0.2.2; }; allow-update { 192.0.2.3; }; };"
        "view \"v1\" { match-clients { 127.0.0.0/8; }; allow-transfer { 192.0.2.12; };"
        "  zone \"a.test\" { type master; file \"z\"; };"
        "  zone \"b.test\" { type master; file \"z\"; allow-transfer { }; allow-update { key k1; }; };"
        "  zone \"e.test\" { type master; file \"z\"; allow-transfer { key k1; 192.0.2.5; }; };"
        "};"
        "view \"v2\" { match-clients { any; };"
        "  zone \"c.test\" { type master; file \"z\"; };"
        "  zone \"f.test\" { type master; file \"z\"; tsig-key k2; };"
        "  zone \"g.test\" { type master; file \"z\"; tsig-key k2; allow-transfer { 192.0.2.7; }; };"
        "  zone \"m.test\" { type master; file \"z\"; tsig-key k2; allow-transfer { key k1; }; };"
        "  zone \"h.test\" { type master; file \"z\"; allow-transfer { 192.0.2.7; key k1; }; transfer-acl-match any; };"
        "  zone \"i.test\" { type master; file \"z\"; allow-transfer { 192.0.2.7; key k1; }; transfer-acl-match all; };"
        "  zone \"j.test\" { type master; file \"z\"; allow-transfer { 192.0.2.7; key k1; }; };"
        "  zone \"k.test\" { type master; file \"z\"; allow-transfer { !{ !192.0.2.7; any; }; key k1; }; };"
        "  zone \"l.test\" { type master; file \"z\"; allow-transfer { 192.0.2.7; !key k1; any; }; };"
        "};", &cfg));
    CHECK(tr_allowed(&cfg, "a.test", "v1", "192.0.2.12", NULL));                   /* the view's list */
    CHECK(!tr_allowed(&cfg, "a.test", "v1", "192.0.2.2", NULL));                   /* not options' */
    CHECK(!tr_allowed(&cfg, "b.test", "v1", "192.0.2.12", NULL));                  /* `{ }` of the zone overrides: nobody */
    CHECK(tr_allowed(&cfg, "c.test", "v2", "192.0.2.2", NULL));                    /* options' list */
    CHECK(!tr_allowed(&cfg, "c.test", "v2", "192.0.2.12", NULL));
    CHECK(!tr_allowed(&cfg, "c.test", "v2", "not an address", NULL));
    CHECK(tr_allowed(&cfg, "e.test", "v1", "198.51.100.1", "k1"));                 /* key first: signed from anywhere */
    CHECK(tr_allowed(&cfg, "e.test", "v1", "192.0.2.5", NULL));
    CHECK(!tr_allowed(&cfg, "e.test", "v1", "198.51.100.1", NULL));
    CHECK(!tr_allowed(&cfg, "e.test", "v1", "198.51.100.1", "k2"));
    /* the zone's tsig-key with a list of addresses: still address AND a request signed with the key (unchanged by the first-match order) */
    CHECK(tr_allowed(&cfg, "f.test", "v2", "192.0.2.2", "k2"));                    /* options' list + the tsig-key */
    CHECK(!tr_allowed(&cfg, "f.test", "v2", "192.0.2.2", NULL));
    CHECK(!tr_allowed(&cfg, "f.test", "v2", "198.51.100.1", "k2"));
    CHECK(!tr_allowed(&cfg, "f.test", "v2", "192.0.2.2", "k1"));                   /* signed, but not with the tsig-key */
    CHECK(tr_allowed(&cfg, "g.test", "v2", "192.0.2.7", "k2"));
    CHECK(!tr_allowed(&cfg, "g.test", "v2", "192.0.2.7", NULL));
    CHECK(!tr_allowed(&cfg, "g.test", "v2", "198.51.100.1", "k2"));
    /* a list of keys only: the tsig-key is one more way in */
    CHECK(tr_allowed(&cfg, "m.test", "v2", "198.51.100.1", "k2") && tr_allowed(&cfg, "m.test", "v2", "198.51.100.1", "k1"));
    CHECK(!tr_allowed(&cfg, "m.test", "v2", "192.0.2.7", NULL));
    /* transfer-acl-match: the flat meaning */
    CHECK(tr_allowed(&cfg, "h.test", "v2", "192.0.2.7", NULL) && tr_allowed(&cfg, "h.test", "v2", "198.51.100.1", "k1"));
    CHECK(!tr_allowed(&cfg, "h.test", "v2", "198.51.100.1", NULL));
    CHECK(!tr_allowed(&cfg, "i.test", "v2", "192.0.2.7", NULL) && !tr_allowed(&cfg, "i.test", "v2", "198.51.100.1", "k1"));
    CHECK(tr_allowed(&cfg, "i.test", "v2", "192.0.2.7", "k1"));
    /* nothing written: first match (address OR key) */
    CHECK(tr_allowed(&cfg, "j.test", "v2", "192.0.2.7", NULL) && tr_allowed(&cfg, "j.test", "v2", "198.51.100.1", "k1"));
    CHECK(!tr_allowed(&cfg, "j.test", "v2", "198.51.100.1", NULL));
    /* BIND's AND idiom */
    CHECK(tr_allowed(&cfg, "k.test", "v2", "192.0.2.7", "k1"));
    CHECK(!tr_allowed(&cfg, "k.test", "v2", "192.0.2.7", NULL) && !tr_allowed(&cfg, "k.test", "v2", "198.51.100.1", "k1"));
    /* a negated key (only in first-match mode) */
    CHECK(tr_allowed(&cfg, "l.test", "v2", "192.0.2.7", "k1"));                    /* the address is first */
    CHECK(!tr_allowed(&cfg, "l.test", "v2", "198.51.100.1", "k1"));                /* !key k1 */
    CHECK(tr_allowed(&cfg, "l.test", "v2", "198.51.100.1", "k2"));                 /* any */
    CHECK(zext(view_find_zone_config(cfg.views->next, "l.test"))->acl.transfer->has_neg_key);

    /* updates: options' allow-update is the default of the zones; first match; `key` */
    CHECK(up_allowed(&cfg, "a.test", "v1", "192.0.2.3", NULL));
    CHECK(!up_allowed(&cfg, "a.test", "v1", "192.0.2.4", NULL));
    CHECK(up_allowed(&cfg, "b.test", "v1", "198.51.100.1", "k1"));                 /* the zone's own list */
    CHECK(!up_allowed(&cfg, "b.test", "v1", "192.0.2.3", NULL));
    CHECK(!up_allowed(&cfg, "b.test", "v1", "192.0.2.3", "k2"));
    free_server_config_fields(&cfg);

    /* update-acl-match any (the meaning allow-update always had) against the first-match default */
    CHECK(parse_cfg(KEYS
        "zone \"a.test\" { type master; file \"z\"; allow-update { !192.0.2.9; 192.0.2.0/24; key k1; }; };"
        "zone \"b.test\" { type master; file \"z\"; allow-update { !192.0.2.9; 192.0.2.0/24; key k1; }; update-acl-match any; };"
        "zone \"c.test\" { type master; file \"z\"; allow-update { 192.0.2.0/24; key k1; }; update-acl-match all; };"
        "zone \"d.test\" { type master; file \"z\"; allow-update { k1; }; };"
        "zone \"e.test\" { type master; file \"z\"; allow-update { }; };", &cfg));
    CHECK(up_allowed(&cfg, "a.test", NULL, "192.0.2.1", NULL));
    CHECK(!up_allowed(&cfg, "a.test", NULL, "192.0.2.9", "k1"));                   /* the negated host is first: not even its key */
    CHECK(up_allowed(&cfg, "a.test", NULL, "198.51.100.1", "k1"));
    CHECK(up_allowed(&cfg, "b.test", NULL, "192.0.2.9", "k1"));                    /* any: a listed key is enough */
    CHECK(!up_allowed(&cfg, "b.test", NULL, "192.0.2.9", NULL));
    CHECK(up_allowed(&cfg, "c.test", NULL, "192.0.2.1", "k1"));
    CHECK(!up_allowed(&cfg, "c.test", NULL, "192.0.2.1", NULL) && !up_allowed(&cfg, "c.test", NULL, "198.51.100.1", "k1"));
    CHECK(up_allowed(&cfg, "d.test", NULL, "198.51.100.1", "k1"));                 /* a bare key name = key k1 (allow-update has always accepted it) */
    CHECK(!up_allowed(&cfg, "e.test", NULL, "192.0.2.1", "k1"));
    /* the flat lists are still there for the settings text and the tools */
    CHECK(zext(view_find_zone_config(cfg.views, "a.test"))->allow_update_count == 3);
    CHECK(zext(view_find_zone_config(cfg.views, "d.test"))->allow_update_count == 1);
    free_server_config_fields(&cfg);

    /* allow-notify: secondary zones only; a `key` element is the TSIG key of the NOTIFY */
    CHECK(parse_cfg(KEYS
        "options { allow-notify { 192.0.2.4; key k1; }; };"
        "zone \"a.test\" { type slave; file \"z\"; masters { 192.0.2.99; }; };"
        "zone \"b.test\" { type slave; file \"z\"; masters { 192.0.2.99; }; allow-notify { none; }; };", &cfg));
    {
        const zone_config_t *za = view_find_zone_config(cfg.views, "a.test"), *zb = view_find_zone_config(cfg.views, "b.test");
        CHECK(zone_notify_acl_allows(&cfg, za, "__default__", "192.0.2.4", NULL));
        CHECK(zone_notify_acl_allows(&cfg, za, "__default__", "198.51.100.1", "k1"));
        CHECK(!zone_notify_acl_allows(&cfg, za, "__default__", "198.51.100.1", NULL));
        CHECK(!zone_notify_acl_allows(&cfg, zb, "__default__", "192.0.2.4", NULL));
    }
    free_server_config_fields(&cfg);
}

static void test_flat_and_refs(void) {
    printf("[TEST] flat lists, reference counting, received settings\n");
    server_config_t cfg;
    CHECK(parse_cfg(KEYS
        "acl net { 192.0.2.0/24; !{ 192.0.2.5; }; };"
        "zone \"a.test\" { type master; file \"z\"; allow-transfer { net; key k1; 198.51.100.1; }; allow-query { net; }; };", &cfg));
    zone_config_t *z = view_find_zone_config(cfg.views, "a.test");
    const zone_ext_t *x = zext(z);
    /* the flat lists are what the old parser built: `!{ x; }` negates each element, the key goes to tsig_keys */
    CHECK(x->allow_transfer_count == 3 && x->tsig_keys_count == 1 && strcmp(x->tsig_keys[0], "k1") == 0);
    CHECK(x->allow_transfer_count == 3 && strcmp(x->allow_transfer[0], "192.0.2.0/24") == 0 && strcmp(x->allow_transfer[1], "!192.0.2.5") == 0 &&
          strcmp(x->allow_transfer[2], "198.51.100.1") == 0);
    CHECK(x->acl.transfer && x->acl.query);
    /* a clone (the zone configuration of a secondary with received settings) shares the lists by reference */
    zone_ext_shared_t *rx = db_settings_parse("additional-from-auth no;", 24, NULL, 0);
    CHECK(rx != NULL);
    if (rx) {
        char note[160];
        zone_config_t *c = zone_config_with_received("a.test.", z, &rx->ext, &cfg, note, sizeof(note));
        CHECK(c && zext(c)->acl.transfer == x->acl.transfer && zext(c)->acl.query == x->acl.query);
        free_zone_config(c);
        zone_ext_shared_unref(rx);
    }
    CHECK(tr_allowed(&cfg, "a.test", "__default__", "192.0.2.7", NULL));           /* net matches */
    CHECK(tr_allowed(&cfg, "a.test", "__default__", "198.51.100.1", NULL));
    CHECK(tr_allowed(&cfg, "a.test", "__default__", "203.0.113.1", "k1"));
    CHECK(tr_allowed(&cfg, "a.test", "__default__", "192.0.2.5", NULL));          /* 192.0.2.0/24 comes first in the acl block, so 192.0.2.5 is let in (first match) */
    free_server_config_fields(&cfg);
}

int main(void) {
    printf("=== BIND address match list tests ===\n");
    test_first_match();
    test_keys();
    test_nested_and_named();
    test_localhost_localnets();
    test_errors();
    test_inheritance();
    test_flat_and_refs();
    printf("[*] %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("=== BIND address match list tests FAILED ===\n");
        return 1;
    }
    printf("=== All BIND address match list tests PASSED ===\n");
    return 0;
}

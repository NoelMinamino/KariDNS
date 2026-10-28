/*
 * test_listen_on.c - listen-on, listen-on-v6, bind-address and blackhole (BIND 9.20 ARM "Interfaces" and "blackhole"):
 * the grammar of the statements (port per statement, any / none / negation / acl names / localhost / localnets, the errors with the place in
 * the file), the set of addresses the parse computes from them (server_config_t.listen: union with bind-address, duplicates, one address
 * with two ports, a wildcard covering the specific addresses of its port, the limit of 64, -p), and the blackhole list.
 *
 * Expectations are worked out from the ARM text and from lib/ns/interfacemgr.c (the list is matched against the interface addresses, a plain
 * `any` is a wildcard socket) by hand for each case.  The interface table is fixed with aml_set_interfaces(), so nothing depends on the host.
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

/* ---- the interface table of the pretend host ---- */
static void add4(aml_iface_t *t, size_t *n, const char *ip, int prefix) {
    aml_iface_t *e = &t[(*n)++];
    memset(e, 0, sizeof(*e));
    e->family = AF_INET;
    inet_pton(AF_INET, ip, e->addr);
    for (int i = 0; i < 4; i++) e->mask[i] = prefix >= 8 * (i + 1) ? 0xff : (prefix <= 8 * i ? 0 : (uint8_t)(0xff << (8 - (prefix - 8 * i))));
}
static void add6(aml_iface_t *t, size_t *n, const char *ip, int prefix) {
    aml_iface_t *e = &t[(*n)++];
    memset(e, 0, sizeof(*e));
    e->family = AF_INET6;
    inet_pton(AF_INET6, ip, e->addr);
    for (int i = 0; i < 16; i++) e->mask[i] = prefix >= 8 * (i + 1) ? 0xff : (prefix <= 8 * i ? 0 : (uint8_t)(0xff << (8 - (prefix - 8 * i))));
}
static void set_host(void) {
    aml_iface_t t[16];
    size_t n = 0;
    add4(t, &n, "127.0.0.1", 8);
    add4(t, &n, "192.0.2.10", 24);
    add4(t, &n, "192.0.2.11", 24);
    add4(t, &n, "198.51.100.7", 24);
    add6(t, &n, "::1", 128);
    add6(t, &n, "2001:db8::10", 64);
    add6(t, &n, "2001:db8::11", 64);
    add6(t, &n, "fe80::1", 64);
    aml_set_interfaces(t, n);
}

/* ---- parse helpers ---- */
static bool parse_cfg(const char *text, server_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    return parse_named_conf(text, cfg) == 0;
}

/* parse with stderr (the [ERROR] / [WARNING] lines) collected in err; returns whether the parse succeeded */
static bool parse_cap(const char *text, server_config_t *cfg, char *err, size_t errsz) {
    char path[] = "/tmp/karidns-listen-test.XXXXXX";
    int fd = mkstemp(path);
    int saved = dup(2);
    err[0] = '\0';
    if (fd < 0 || saved < 0) return parse_cfg(text, cfg);
    fflush(stderr);
    dup2(fd, 2);
    bool ok = parse_cfg(text, cfg);
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

static bool has_addr(const server_config_t *c, const char *text, int port) {
    for (int i = 0; i < c->listen_count; i++)
        if (strcmp(c->listen[i].text, text) == 0 && c->listen[i].port == port) return true;
    return false;
}

/* parse text: success, and the computed list is exactly the "addr:port" items of want (separated by spaces, order ignored) */
static bool listen_is(const char *text, const char *want) {
    server_config_t c;
    char err[2048];
    if (!parse_cap(text, &c, err, sizeof(err))) {
        printf("  [info] parse failed: %s\n  [info] text: %s\n", err, text);
        return false;
    }
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", want);
    int expected = 0;
    bool ok = true;
    for (char *tok = strtok(copy, " "); tok; tok = strtok(NULL, " ")) {
        char *colon = strrchr(tok, ':');
        int port = atoi(colon + 1);
        *colon = '\0';
        expected++;
        if (!has_addr(&c, tok, port)) {
            printf("  [info] missing %s:%d in:", tok, port);
            for (int i = 0; i < c.listen_count; i++) printf(" %s:%d", c.listen[i].text, (int)c.listen[i].port);
            printf("\n");
            ok = false;
        }
    }
    if (c.listen_count != expected) {
        printf("  [info] expected %d addresses, got %d:", expected, c.listen_count);
        for (int i = 0; i < c.listen_count; i++) printf(" %s:%d", c.listen[i].text, (int)c.listen[i].port);
        printf("\n");
        ok = false;
    }
    free_server_config_fields(&c);
    return ok;
}

/* parse text: must fail, and the message must contain frag */
static bool fails_with(const char *text, const char *frag) {
    server_config_t c;
    char err[2048];
    bool ok = parse_cap(text, &c, err, sizeof(err));
    if (ok) {
        free_server_config_fields(&c);
        printf("  [info] parse unexpectedly succeeded: %s\n", text);
        return false;
    }
    if (!strstr(err, frag)) {
        printf("  [info] message lacks '%s': %s\n", frag, err);
        return false;
    }
    return true;
}

#define V6ANY "listen-on-v6 { any; };"
#define V6NONE "listen-on-v6 { none; };"

static void test_defaults(void) {
    printf("[TEST] defaults and bind-address alone...\n");
    /* neither listen-on nor bind-address: 0.0.0.0 and :: (BIND 9.20: "all IPv4 interfaces", "all IPv6 interfaces") */
    CHECK(listen_is("options { };", "0.0.0.0:53 :::53"));
    CHECK(listen_is("options { port 5300; };", "0.0.0.0:5300 :::5300"));
    /* bind-address alone is exactly the list written (no wildcard of the other family) */
    CHECK(listen_is("options { bind-address { 127.0.0.1; }; port 5300; };", "127.0.0.1:5300"));
    CHECK(listen_is("options { bind-address 192.0.2.10; };", "192.0.2.10:53"));
    CHECK(listen_is("options { bind-address { 127.0.0.1; ::1; }; };", "127.0.0.1:53 ::1:53"));
    /* a bind-address that is no address used to bind nothing, silently */
    CHECK(fails_with("options {\n bind-address { localhost; };\n};", "bind-address: 'localhost' is not an IPv4 or IPv6 address"));
    CHECK(fails_with("options { bind-address { 127.0.0.1; 192.0.2.300; }; };", "line 1"));
}

static void test_grammar_and_ports(void) {
    printf("[TEST] listen-on grammar, port per statement...\n");
    set_host();
    /* ARM example: no port = options { port } (53 by default); `port` before the braces; several statements */
    CHECK(listen_is("options { listen-on { 127.0.0.1; }; " V6NONE " };", "127.0.0.1:53"));
    CHECK(listen_is("options { listen-on port 5301 { 127.0.0.1; }; " V6NONE " };", "127.0.0.1:5301"));
    CHECK(listen_is("options { listen-on { 127.0.0.1; }; " V6NONE " port 5300; };", "127.0.0.1:5300"));   /* options port after the statement */
    CHECK(listen_is("options { port 5300; listen-on port 5301 { 127.0.0.1; }; listen-on { 192.0.2.10; }; " V6NONE " };",
                    "127.0.0.1:5301 192.0.2.10:5300"));
    CHECK(listen_is("options { listen-on port 53 { 127.0.0.1; }; listen-on port 5353 { 192.0.2.10; }; listen-on-v6 port 5354 { ::1; }; };",
                    "127.0.0.1:53 192.0.2.10:5353 ::1:5354"));
    /* a statement for one family leaves the other at its default wildcard (BIND's default of listen-on-v6 is every IPv6 interface) */
    CHECK(listen_is("options { listen-on { 127.0.0.1; }; };", "127.0.0.1:53 :::53"));
    CHECK(listen_is("options { listen-on-v6 { ::1; }; };", "0.0.0.0:53 ::1:53"));
    /* the empty list matches nothing */
    CHECK(listen_is("options { listen-on { }; listen-on-v6 { ::1; }; };", "::1:53"));
    /* an element of the other family selects nothing (a warning) */
    {
        server_config_t c;
        char err[1024];
        CHECK(parse_cap("options { listen-on { 2001:db8::10; 127.0.0.1; }; " V6NONE " };", &c, err, sizeof(err)));
        CHECK(strstr(err, "IPv6 address in listen-on") != NULL);
        CHECK(c.listen_count == 1 && has_addr(&c, "127.0.0.1", 53));
        free_server_config_fields(&c);
    }
    /* the keywords come in any order (lib/isccfg/namedconf.c); errors carry the line */
    CHECK(fails_with("options {\n listen-on port 0 { 127.0.0.1; };\n};", "line 2: options listen-on: port: invalid port '0'"));
    CHECK(fails_with("options { listen-on port 70000 { 127.0.0.1; }; };", "invalid port '70000'"));
    CHECK(fails_with("options { listen-on port abc { 127.0.0.1; }; };", "invalid port 'abc'"));
    CHECK(fails_with("options { listen-on port { 127.0.0.1; }; };", "invalid port"));
    CHECK(fails_with("options { listen-on port 53 port 54 { 127.0.0.1; }; };", "'port' is given twice"));
    CHECK(fails_with("options { listen-on foo { 127.0.0.1; }; };", "expected 'port' or '{' but found 'foo'"));
    CHECK(fails_with("options { listen-on 127.0.0.1; };", "expected 'port' or '{'"));
    CHECK(fails_with("options { listen-on { 127.0.0.1; } };", "expected ';' after '}'"));
    CHECK(fails_with("options { listen-on { 127.0.0.1 }; };", "expected ';' after the element"));
    CHECK(fails_with("options {\n listen-on-v6 {\n ::1;\n", "end of file"));   /* unterminated */
    /* tls, http and proxy: refused, not silently served in plain DNS */
    CHECK(fails_with("options {\n listen-on port 853 tls ephemeral { 127.0.0.1; };\n};", "line 2: options listen-on: 'tls' is not supported"));
    CHECK(fails_with("options { listen-on-v6 http default { ::1; }; };", "'http' is not supported"));
    CHECK(fails_with("options { listen-on proxy plain { 127.0.0.1; }; };", "'proxy' is not supported"));
    CHECK(fails_with("options { listen-on tls none http local { 127.0.0.1; }; };", "'tls' is not supported"));
}

static void test_match_lists(void) {
    printf("[TEST] address match lists against the interface table...\n");
    set_host();
    /* plain any: the wildcard (BIND: one wildcard socket for IPv6 any; the IPv4 wildcard is this server's choice, see config_build_listen) */
    CHECK(listen_is("options { listen-on { any; }; " V6ANY " };", "0.0.0.0:53 :::53"));
    CHECK(listen_is("options { listen-on port 5300 { any; }; " V6NONE " };", "0.0.0.0:5300"));
    CHECK(listen_is("acl everyone { any; };\noptions { listen-on { everyone; }; " V6NONE " };", "0.0.0.0:53"));
    CHECK(listen_is("options { listen-on { { any; }; }; " V6NONE " };", "0.0.0.0:53"));
    /* none: nothing; listen-on-v6 { none; } opens no IPv6 (ARM) */
    CHECK(listen_is("options { listen-on { 127.0.0.1; }; listen-on-v6 { none; }; };", "127.0.0.1:53"));
    CHECK(listen_is("options { listen-on { none; }; listen-on-v6 { ::1; }; };", "::1:53"));
    /* a prefix selects every interface address inside it */
    CHECK(listen_is("options { listen-on { 192.0.2.0/24; }; " V6NONE " };", "192.0.2.10:53 192.0.2.11:53"));
    CHECK(listen_is("options { listen-on-v6 { 2001:db8::/32; }; listen-on { none; }; };", "2001:db8::10:53 2001:db8::11:53"));
    /* negation: first match decides; the ARM's "1.2.3/24; ! 1.2.3.13;" lesson: the exception goes first */
    CHECK(listen_is("options { listen-on { !192.0.2.11; 192.0.2.0/24; }; " V6NONE " };", "192.0.2.10:53"));
    CHECK(listen_is("options { listen-on { 192.0.2.0/24; !192.0.2.11; }; " V6NONE " };", "192.0.2.10:53 192.0.2.11:53"));
    /* not a plain any: every interface address the list allows, one socket each */
    CHECK(listen_is("options { listen-on { !127.0.0.1; any; }; " V6NONE " };", "192.0.2.10:53 192.0.2.11:53 198.51.100.7:53"));
    CHECK(listen_is("options { listen-on { any; 127.0.0.1; }; " V6NONE " };", "127.0.0.1:53 192.0.2.10:53 192.0.2.11:53 198.51.100.7:53"));
    /* ARM: "!2001:db8::/32; any;" for IPv6 = every address outside the prefix; the link-local one has no scope in the table and is skipped */
    CHECK(listen_is("options { listen-on-v6 { !2001:db8::/32; any; }; listen-on { none; }; };", "::1:53"));
    CHECK(listen_is("options { listen-on-v6 { any; ::1; }; listen-on { none; }; };", "::1:53 2001:db8::10:53 2001:db8::11:53"));
    /* acl names, nested lists, localhost and localnets */
    CHECK(listen_is("acl lan { 192.0.2.0/24; };\noptions { listen-on { lan; }; " V6NONE " };", "192.0.2.10:53 192.0.2.11:53"));
    CHECK(listen_is("options { listen-on { !{ 192.0.2.10; }; 192.0.2.0/24; }; " V6NONE " };", "192.0.2.11:53"));   /* a negated nested list */
    CHECK(listen_is("options { listen-on { localhost; }; " V6NONE " };", "127.0.0.1:53 192.0.2.10:53 192.0.2.11:53 198.51.100.7:53"));
    CHECK(listen_is("options { listen-on { localnets; }; " V6NONE " };", "127.0.0.1:53 192.0.2.10:53 192.0.2.11:53 198.51.100.7:53"));
    CHECK(listen_is("options { listen-on { !localhost; any; }; " V6NONE " };", ""));   /* every address is an interface address: nothing is left */
    /* an unknown name and a key are errors with the place */
    CHECK(fails_with("options {\n listen-on {\n nosuchacl;\n };\n};", "line 3: options listen-on: entry 'nosuchacl' is not an address"));
    CHECK(fails_with("key \"k\" { algorithm hmac-sha256; secret \"c2VjcmV0LW9uZS1mb3ItdGVzdA==\"; };\noptions { listen-on { key k; }; };",
                     "'key' elements cannot be used"));
    CHECK(fails_with("options { listen-on { 192.0.2.0/33; }; };", "is not an address"));
    /* an address that is on no interface of the host is a warning, nothing is bound for it (BIND does not bind it either) */
    {
        server_config_t c;
        char err[1024];
        CHECK(parse_cap("options {\n listen-on { 203.0.113.9; 127.0.0.1; };\n " V6NONE "\n};", &c, err, sizeof(err)));
        CHECK(strstr(err, "[WARNING] line 2: options listen-on: '203.0.113.9' matches no address of an interface") != NULL);
        CHECK(c.listen_count == 1 && has_addr(&c, "127.0.0.1", 53));
        free_server_config_fields(&c);
        CHECK(parse_cap("options { listen-on { none; }; " V6NONE " };", &c, err, sizeof(err)));   /* nowhere: parses, warns; the server refuses to start */
        CHECK(c.listen_count == 0 && c.listen == NULL);
        CHECK(strstr(err, "select no address") != NULL);
        free_server_config_fields(&c);
    }
}

static void test_union_and_conflicts(void) {
    printf("[TEST] union with bind-address, duplicates, one address with two ports, wildcard coverage...\n");
    set_host();
    CHECK(listen_is("options { bind-address { 192.0.2.10; }; listen-on { 127.0.0.1; }; " V6NONE " };", "127.0.0.1:53 192.0.2.10:53"));
    CHECK(listen_is("options { bind-address { 192.0.2.10; }; listen-on { 127.0.0.1; }; };", "127.0.0.1:53 192.0.2.10:53 :::53"));   /* v6: only a default */
    CHECK(listen_is("options { bind-address { 192.0.2.10; ::1; }; listen-on { 127.0.0.1; }; };", "127.0.0.1:53 192.0.2.10:53 ::1:53"));   /* bind-address names v6 */
    /* the same address twice is one socket */
    CHECK(listen_is("options { bind-address { 127.0.0.1; }; listen-on { 127.0.0.1; 192.0.2.10; }; " V6NONE " };", "127.0.0.1:53 192.0.2.10:53"));
    CHECK(listen_is("options { listen-on { 127.0.0.1; }; listen-on { 127.0.0.1; }; " V6NONE " };", "127.0.0.1:53"));
    CHECK(listen_is("options { port 5300; bind-address { 127.0.0.1; 127.0.0.1; }; };", "127.0.0.1:5300"));
    /* the same address on two ports is an error naming both places */
    CHECK(fails_with("options {\n listen-on port 53 { 192.0.2.10; };\n listen-on port 54 { 192.0.2.10; };\n " V6NONE "\n};",
                     "line 3: options listen-on: address 192.0.2.10 is listened on at port 53 (line 2) and at port 54"));
    CHECK(fails_with("options {\n bind-address { 192.0.2.10; };\n listen-on port 5353 { 192.0.2.10; };\n};", "listened on at port 5353 (line 3) and at port 53"));
    CHECK(fails_with("options { listen-on port 53 { any; }; listen-on port 54 { any; }; };", "0.0.0.0 is listened on at port 53"));
    CHECK(fails_with("options { listen-on-v6 port 53 { any; }; listen-on-v6 port 54 { any; }; };", ":: is listened on at port 53"));
    /* different addresses may have different ports; a wildcard and a specific address on another port coexist */
    CHECK(listen_is("options { listen-on port 53 { any; }; listen-on port 5353 { 127.0.0.1; }; " V6NONE " };", "0.0.0.0:53 127.0.0.1:5353"));
    /* a wildcard covers the specific addresses of the same family and port: they are dropped */
    CHECK(listen_is("options { listen-on { any; }; bind-address { 127.0.0.1; }; " V6NONE " };", "0.0.0.0:53"));
    CHECK(listen_is("options { bind-address { 127.0.0.1; 0.0.0.0; ::1; }; };", "0.0.0.0:53 ::1:53"));
    CHECK(listen_is("options { listen-on-v6 { any; }; listen-on-v6 { ::1; }; listen-on { none; }; };", ":::53"));
    /* -p replaces options { port } and every statement's port (the command line beats the file, as it did when the file had one port) */
    config_set_port_override(5999);
    {
        server_config_t c;
        char err[512];
        CHECK(parse_cap("options { port 5300; listen-on port 53 { 127.0.0.1; }; listen-on port 54 { 192.0.2.10; }; " V6NONE " };", &c, err, sizeof(err)));
        CHECK(c.port == 5999 && c.listen_count == 2 && has_addr(&c, "127.0.0.1", 5999) && has_addr(&c, "192.0.2.10", 5999));
        free_server_config_fields(&c);
        /* with every port equal, "one address with two ports" cannot happen any more */
        CHECK(parse_cap("options { listen-on port 53 { 127.0.0.1; }; listen-on port 54 { 127.0.0.1; }; " V6NONE " };", &c, err, sizeof(err)));
        CHECK(c.listen_count == 1 && has_addr(&c, "127.0.0.1", 5999));
        free_server_config_fields(&c);
        CHECK(parse_cap("options { bind-address { 127.0.0.1; }; };", &c, err, sizeof(err)));
        CHECK(c.listen_count == 1 && has_addr(&c, "127.0.0.1", 5999));
        free_server_config_fields(&c);
    }
    config_set_port_override(0);
    CHECK(listen_is("options { bind-address { 127.0.0.1; }; };", "127.0.0.1:53"));
}

static void test_limit(void) {
    printf("[TEST] the limit of %d addresses...\n", KARIDNS_LISTEN_MAX);
    aml_iface_t t[200];
    size_t n = 0;
    for (int i = 1; i <= 64; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i);
        add4(t, &n, ip, 24);
    }
    aml_set_interfaces(t, n);
    /* 64 addresses fit (IPv6 off so the default :: does not make 65) */
    {
        server_config_t c;
        char err[512];
        CHECK(parse_cap("options { listen-on { 10.0.0.0/24; }; " V6NONE " };", &c, err, sizeof(err)));
        CHECK(c.listen_count == 64);
        free_server_config_fields(&c);
        /* the 65th address (here the default wildcard of IPv6) is an error */
        CHECK(!parse_cap("options { listen-on { 10.0.0.0/24; }; };", &c, err, sizeof(err)));
        CHECK(strstr(err, "more than 64 addresses to listen on") != NULL);
        /* any is one socket however many interfaces there are */
        CHECK(parse_cap("options { listen-on { any; }; };", &c, err, sizeof(err)));
        CHECK(c.listen_count == 2);
        free_server_config_fields(&c);
    }
    add4(t, &n, "10.0.0.65", 24);
    aml_set_interfaces(t, n);
    CHECK(fails_with("options {\n listen-on { 10.0.0.0/24; };\n " V6NONE "\n};", "line 2: options listen-on: more than 64 addresses"));
    /* bind-address counts the same */
    {
        char text[4096];
        size_t o = (size_t)snprintf(text, sizeof(text), "options { bind-address {");
        for (int i = 1; i <= 65; i++) o += (size_t)snprintf(text + o, sizeof(text) - o, " 10.1.0.%d;", i);
        snprintf(text + o, sizeof(text) - o, " }; };");
        CHECK(fails_with(text, "more than 64 addresses"));
    }
    set_host();
}

static void test_blackhole(void) {
    printf("[TEST] blackhole...\n");
    set_host();
    server_config_t c;
    char err[1024];
    uint8_t b[16];
    aml_subject_t s;
    /* not written: BIND's default is none */
    CHECK(parse_cap("options { };", &c, err, sizeof(err)));
    CHECK(c.blackhole == NULL);
    free_server_config_fields(&c);
    /* a prefix: a non-negated match drops (lib/ns/client.c: dns_acl_match() > 0) */
    CHECK(parse_cap("options { blackhole { 192.0.2.0/24; 2001:db8:bad::/48; }; };", &c, err, sizeof(err)));
    CHECK(c.blackhole != NULL);
    aml_subject_from_ip(&s, b, "192.0.2.77", NULL);
    CHECK(aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "198.51.100.1", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "2001:db8:bad::5", NULL);
    CHECK(aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "2001:db8::5", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    free_server_config_fields(&c);
    /* the ARM's warning: "!address;" alone exempts address and drops nothing else; "!address; any;" drops everything but address */
    CHECK(parse_cap("options { blackhole { !192.0.2.1; }; };", &c, err, sizeof(err)));
    aml_subject_from_ip(&s, b, "192.0.2.1", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "192.0.2.2", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    free_server_config_fields(&c);
    CHECK(parse_cap("options { blackhole { !192.0.2.1; any; }; };", &c, err, sizeof(err)));
    aml_subject_from_ip(&s, b, "192.0.2.1", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "192.0.2.2", NULL);
    CHECK(aml_allows(c.blackhole, &s));
    free_server_config_fields(&c);
    /* acl names, localhost; an unknown name, a key and a `port` in front are errors with the line */
    CHECK(parse_cap("acl bad { 192.0.2.0/25; };\noptions { blackhole { bad; 198.51.100.0/24; }; };", &c, err, sizeof(err)));
    aml_subject_from_ip(&s, b, "192.0.2.100", NULL);
    CHECK(aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "192.0.2.200", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    free_server_config_fields(&c);
    CHECK(fails_with("options {\n blackhole { nosuch; };\n};", "line 2: options blackhole: entry 'nosuch' is not an address"));
    CHECK(fails_with("key \"k\" { algorithm hmac-sha256; secret \"c2VjcmV0LW9uZS1mb3ItdGVzdA==\"; };\noptions { blackhole { key k; }; };",
                     "'key' elements cannot be used"));
    CHECK(fails_with("options { blackhole 192.0.2.1; };", "expected '{'"));
    CHECK(fails_with("options { blackhole { 192.0.2.1; }; };\n" "options { blackhole { 192.0.2.1 }; };", "expected ';'"));
    /* the second statement replaces the first */
    CHECK(parse_cap("options { blackhole { 192.0.2.0/24; }; blackhole { 198.51.100.0/24; }; };", &c, err, sizeof(err)));
    aml_subject_from_ip(&s, b, "192.0.2.5", NULL);
    CHECK(!aml_allows(c.blackhole, &s));
    aml_subject_from_ip(&s, b, "198.51.100.5", NULL);
    CHECK(aml_allows(c.blackhole, &s));
    free_server_config_fields(&c);
    /* blackhole does not change what is listened on */
    CHECK(listen_is("options { blackhole { 192.0.2.0/24; }; bind-address { 127.0.0.1; }; };", "127.0.0.1:53"));
}

int main(void) {
    test_defaults();
    test_grammar_and_ports();
    test_match_lists();
    test_union_and_conflicts();
    test_limit();
    test_blackhole();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("test_listen_on: FAILED\n");
        return 1;
    }
    printf("test_listen_on: all passed\n");
    return 0;
}

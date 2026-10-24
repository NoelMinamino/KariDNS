/*
 * test_config_directives.c - table-driven tests for named.conf directive parsing.
 *
 * Coverage gap this closes (dns_config_parser.c): the options{} / zone{} / key{} / control-channel{} /
 * logging{} / dnstap{} directive handlers, the ecs-tags / location-tags blocks, ACL negation, and the
 * post-parse semantic validation had almost no direct tests; only the paths the integration
 * scripts happened to touch were executed.
 *
 * Expectations come from the documented semantics of each directive (BIND 9 named.conf syntax where
 * one exists, README.md for the KariDNS extensions) and from independent computations (e.g. the
 * base64 secret is decoded with Python, not with KariDNS), never from running the parser and pasting
 * its output. Every rejection case is a genuinely malformed input.
 *
 * A failing parse frees the partially built configuration itself (parse_named_conf_ext), so
 * expect_reject() must not free again; parse_ok() configs are released with
 * free_server_config_fields().
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "../dns_config_parser.h"
#include "test_zext.h"
#include "../dns_utils.h"
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

#define CHECK_MSG(cond, ...) do { \
    g_checks++; \
    if (!(cond)) { g_failed++; printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

#define CHECK_STR(actual, expected) do { \
    g_checks++; \
    const char *a_ = (actual); const char *e_ = (expected); \
    if (!a_ || strcmp(a_, e_) != 0) { \
        g_failed++; \
        printf("  [FAIL] %s:%d: %s == \"%s\" (got \"%s\")\n", __FILE__, __LINE__, #actual, e_, a_ ? a_ : "(null)"); \
    } \
} while (0)

/* The parser reports errors on stderr; keep the test output readable. */
static int parse_quiet(const char *txt, server_config_t *cfg) {
    fflush(stderr);
    int saved = dup(2);
    int nul = open("/dev/null", O_WRONLY);
    if (nul >= 0) { dup2(nul, 2); close(nul); }
    int rc = parse_named_conf(txt, cfg);
    fflush(stderr);
    if (saved >= 0) { dup2(saved, 2); close(saved); }
    return rc;
}

static bool parse_ok(const char *txt, server_config_t *cfg) {
    int rc = parse_quiet(txt, cfg);
    CHECK(rc == 0);
    if (rc != 0) printf("         (config was: %s)\n", txt);
    return rc == 0;
}

static void expect_reject(const char *label, const char *txt) {
    server_config_t cfg;
    int rc = parse_quiet(txt, &cfg);
    g_checks++;
    if (rc != -1) {
        g_failed++;
        printf("  [FAIL] should be rejected but parsed (rc=%d): %s\n         %s\n", rc, label, txt);
        if (rc == 0) free_server_config_fields(&cfg);
    }
}

static const zone_config_t *first_zone(const server_config_t *cfg) {
    return (cfg->views && cfg->views->zones) ? cfg->views->zones : NULL;
}

#define SECRET_OK "k7e8vW8f0W4v9B+5Y8f0W4v9B+5Y8f0W4v9B+5Y8f0U="  /* decodes to 32 bytes */
#define ZONE_MIN "zone \"example.com\" { type master; file \"example.com.zone\"; };"

/* ------------------------------------------------------------------------ */
static void test_defaults(void) {
    printf("[TEST] defaults of an empty options block...\n");
    server_config_t cfg;
    if (!parse_ok("options { };", &cfg)) return;
    CHECK(cfg.port == 53);
    CHECK(cfg.serve_stale == true);
    CHECK(cfg.send_extended_errors == true);
    CHECK(cfg.tcp_connection_reuse == false);
    CHECK(cfg.tcp_idle_timeout == 10000);
    CHECK(cfg.minimal_responses == false);
    CHECK(cfg.minimal_any == false);
    CHECK(cfg.minimal_any_ttl == 86400);
    CHECK(cfg.query_log_max_qps == 5000);
    CHECK(cfg.query_log_buffer_size == 32768);
    CHECK(cfg.max_mqtypes == 4);
    CHECK(cfg.rfc10029_mqtype_enable == false);
    CHECK(cfg.ecs_enable == false);
    CHECK(cfg.allow_program_zones == false);
    CHECK(cfg.additional_from_auth == ADDITIONAL_AUTH_YES);
    CHECK(cfg.udp_recvbuf_size == 4 * 1024 * 1024);
    CHECK(cfg.udp_sndbuf_size == 4 * 1024 * 1024);
    CHECK(cfg.tcp_mss == 0);                /* 0 = leave the OS default alone */
    CHECK(cfg.tcp_window == 0);
    CHECK(cfg.udp_bufsize == 0);            /* 0 = the built-in 1232 */
    CHECK(cfg.any_zone_tcp_opts == false);
    CHECK(cfg.cookie_secret_count == 0);
    CHECK(cfg.dnstap.enabled == false);
    CHECK(cfg.control.enabled == false);
    free_server_config_fields(&cfg);
}

/* ------------------------------------------------------------------------ */
static void test_boolean_directives(void) {
    printf("[TEST] boolean options directives (yes/true/no/false)...\n");
    static const struct { const char *name; size_t off; bool dflt; } dirs[] = {
        { "ecs-enable",           offsetof(server_config_t, ecs_enable),             false },
        { "send-extended-errors", offsetof(server_config_t, send_extended_errors),   true  },
        { "serve-stale",          offsetof(server_config_t, serve_stale),            true  },
        { "rfc10029-mqtype",      offsetof(server_config_t, rfc10029_mqtype_enable), false },
        { "tcp-connection-reuse", offsetof(server_config_t, tcp_connection_reuse),   false },
        { "allow-program-zones",  offsetof(server_config_t, allow_program_zones),    false },
        { "minimal-responses",    offsetof(server_config_t, minimal_responses),      false },
        { "minimal-any",          offsetof(server_config_t, minimal_any),            false },
    };
    /* D-02: BIND と同じく yes/true/1 と no/false/0、大文字小文字は区別しない */
    static const struct { const char *word; bool value; } words[] = {
        { "yes", true }, { "true", true }, { "no", false }, { "false", false },
        { "YES", true }, { "True", true }, { "1", true }, { "No", false }, { "FALSE", false }, { "0", false },
    };
    char txt[256];
    for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
        for (size_t w = 0; w < sizeof(words) / sizeof(words[0]); w++) {
            snprintf(txt, sizeof(txt), "options { %s %s; };", dirs[d].name, words[w].word);
            server_config_t cfg;
            if (!parse_ok(txt, &cfg)) continue;
            bool got = *(const bool *)((const char *)&cfg + dirs[d].off);
            CHECK(got == words[w].value);
            free_server_config_fields(&cfg);
        }
        /* D-02: any other value is a configuration error (it used to be ignored silently) */
        snprintf(txt, sizeof(txt), "options { %s maybe; };", dirs[d].name);
        expect_reject("boolean option with value 'maybe'", txt);
        snprintf(txt, sizeof(txt), "options { %s 2; };", dirs[d].name);
        expect_reject("boolean option with value '2'", txt);
        /* an unrelated directive must leave the default untouched */
        server_config_t cfg;
        if (parse_ok("options { port 5353; };", &cfg)) {
            CHECK(*(const bool *)((const char *)&cfg + dirs[d].off) == dirs[d].dflt);
            free_server_config_fields(&cfg);
        }
    }
    server_config_t cfg;
    if (parse_ok("options { minimal-responses yes; minimal-any yes; };", &cfg)) {
        CHECK(cfg.minimal_responses == true);
        CHECK(cfg.minimal_any == true);
        free_server_config_fields(&cfg);
    }
}

/* ------------------------------------------------------------------------ */
static void test_numeric_directives(void) {
    printf("[TEST] numeric options directives: valid values and boundaries...\n");
    server_config_t cfg;

    if (parse_ok("options { tcp-initial-timeout 1500; tcp-idle-timeout 4294967295; };", &cfg)) {
        CHECK(cfg.tcp_initial_timeout == 1500);
        CHECK(cfg.tcp_idle_timeout == 4294967295u);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { port 5353; tcp-idle-timeout 0; query-log-max-qps 250; "
                 "minimal-any-ttl 300; wire-cache-max-records 12345; };", &cfg)) {
        CHECK(cfg.port == 5353);
        CHECK(cfg.tcp_idle_timeout == 0);
        CHECK(cfg.tcp_initial_timeout == 10000);   /* D-06: default */
        CHECK(cfg.query_log_max_qps == 250);
        CHECK(cfg.minimal_any_ttl == 300);
        CHECK(cfg.wire_cache_max_records == 12345);
        free_server_config_fields(&cfg);
    }

    /* query-log-buffer-size: power of two in [1024, 1048576] */
    static const uint32_t good_sizes[] = { 1024, 2048, 65536, 1048576 };
    for (size_t i = 0; i < sizeof(good_sizes) / sizeof(good_sizes[0]); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "options { query-log-buffer-size %u; };", good_sizes[i]);
        if (parse_ok(txt, &cfg)) { CHECK(cfg.query_log_buffer_size == good_sizes[i]); free_server_config_fields(&cfg); }
    }
    static const char *bad_sizes[] = { "1000", "512", "0", "1025", "2097152", "abc", "4096x" };
    for (size_t i = 0; i < sizeof(bad_sizes) / sizeof(bad_sizes[0]); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "options { query-log-buffer-size %s; };", bad_sizes[i]);
        expect_reject(bad_sizes[i], txt);
    }

    /* max-mqtypes clamps to [0, 16]; garbage is ignored (keeps the default of 4) */
    static const struct { const char *in; int expect; } mq[] = {
        { "0", 0 }, { "7", 7 }, { "16", 16 }, { "99", 16 }, { "-3", 0 }, { "abc", 4 },
    };
    for (size_t i = 0; i < sizeof(mq) / sizeof(mq[0]); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "options { max-mqtypes %s; };", mq[i].in);
        if (parse_ok(txt, &cfg)) { CHECK(cfg.max_mqtypes == mq[i].expect); free_server_config_fields(&cfg); }
    }
}

static void test_numeric_directives_invalid(void) {
    printf("[TEST] numeric options directives: malformed values are rejected...\n");
    static const char *cases[] = {
        "options { tcp-idle-timeout -1; };",
        "options { tcp-idle-timeout abc; };",
        "options { tcp-idle-timeout 10s; };",
        "options { tcp-initial-timeout -1; };",
        "options { tcp-initial-timeout 2.5; };",
        "options { tcp-idle-timeout 4294967296; };",
        "options { query-log-max-qps abc; };",
        "options { minimal-any-ttl -1; };",
        "options { minimal-any-ttl 1.5; };",
        "options { wire-cache-max-records -1; };",
        "options { wire-cache-max-records lots; };",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) expect_reject(cases[i], cases[i]);
}

static void test_buffer_sizes(void) {
    printf("[TEST] udp-recvbuf-size / udp-sndbuf-size unit suffixes...\n");
    static const struct { const char *in; int expect; } t[] = {
        { "65536",  65536 },
        { "512k",   512 * 1024 },
        { "512K",   512 * 1024 },
        { "2m",     2 * 1024 * 1024 },
        { "2M",     2 * 1024 * 1024 },
        { "1g",     1024 * 1024 * 1024 },
        { "4G",     INT_MAX },              /* clamped */
        { "0",      4 * 1024 * 1024 },      /* non-positive: ignored, default kept */
        { "-8k",    4 * 1024 * 1024 },
        { "junk",   4 * 1024 * 1024 },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        char txt[128];
        server_config_t cfg;
        snprintf(txt, sizeof(txt), "options { udp-recvbuf-size %s; udp-sndbuf-size %s; };", t[i].in, t[i].in);
        if (parse_ok(txt, &cfg)) {
            CHECK(cfg.udp_recvbuf_size == t[i].expect);
            CHECK(cfg.udp_sndbuf_size == t[i].expect);
            free_server_config_fields(&cfg);
        }
    }
}

static void test_transport_params(void) {
    printf("[TEST] tcp-mss / tcp-window / udp-bufsize and their zone-* overrides...\n");
    server_config_t cfg;

    /* options{}: plain integers, K/M suffixes on the window only */
    if (parse_ok("options { tcp-mss 1220; tcp-window 256k; udp-bufsize 1400; };", &cfg)) {
        CHECK(cfg.tcp_mss == 1220);
        CHECK(cfg.tcp_window == 256 * 1024);
        CHECK(cfg.udp_bufsize == 1400);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { tcp-window 4M; };", &cfg)) {
        CHECK(cfg.tcp_window == 4 * 1024 * 1024);
        free_server_config_fields(&cfg);
    }
    /* range boundaries are inclusive */
    if (parse_ok("options { tcp-mss 536; tcp-window 4096; udp-bufsize 512; };", &cfg)) {
        CHECK(cfg.tcp_mss == 536);
        CHECK(cfg.tcp_window == 4096);
        CHECK(cfg.udp_bufsize == 512);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { tcp-mss 65495; tcp-window 64M; udp-bufsize 4096; };", &cfg)) {
        CHECK(cfg.tcp_mss == 65495);
        CHECK(cfg.tcp_window == 64 * 1024 * 1024);
        CHECK(cfg.udp_bufsize == 4096);
        free_server_config_fields(&cfg);
    }

    /* zone{} overrides; the global flag tracks whether any zone uses zone-tcp-* */
    if (parse_ok("zone \"a.example\" { type master; file \"a.zone\"; zone-tcp-mss 1200; zone-tcp-window 128k;"
                 " zone-tcp-sndbuf 2M; zone-udp-bufsize 1400; };"
                 "zone \"b.example\" { type master; file \"b.zone\"; };", &cfg)) {
        const zone_config_t *a = first_zone(&cfg);
        const zone_config_t *b = a ? a->next : NULL;
        CHECK(a && zext(a)->zone_tcp_mss == 1200);
        CHECK(a && zext(a)->zone_tcp_window == 128 * 1024);
        CHECK(a && zext(a)->zone_tcp_sndbuf == 2 * 1024 * 1024);
        CHECK(a && zext(a)->zone_udp_bufsize == 1400);
        CHECK(b && zext(b)->zone_tcp_mss == 0 && zext(b)->zone_tcp_window == 0 && zext(b)->zone_tcp_sndbuf == 0);
        CHECK(b && zext(b)->zone_udp_bufsize == 0);
        CHECK(cfg.any_zone_tcp_opts == true);
        free_server_config_fields(&cfg);
    }
    /* zone-udp-bufsize alone does not touch the TCP path */
    if (parse_ok("zone \"a.example\" { type master; file \"a.zone\"; zone-udp-bufsize 1232; };", &cfg)) {
        CHECK(cfg.any_zone_tcp_opts == false);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"a.example\" { type master; file \"a.zone\"; zone-tcp-sndbuf 1m; };", &cfg)) {
        CHECK(cfg.any_zone_tcp_opts == true);
        free_server_config_fields(&cfg);
    }

    /* out-of-range and malformed values are rejected, never silently clamped */
    expect_reject("tcp-mss below RFC 1122 default", "options { tcp-mss 535; };");
    expect_reject("tcp-mss above 65535-40", "options { tcp-mss 65496; };");
    expect_reject("tcp-mss with suffix", "options { tcp-mss 1k; };");
    expect_reject("tcp-mss negative", "options { tcp-mss -1220; };");
    expect_reject("tcp-mss trailing junk", "options { tcp-mss 1220x; };");
    expect_reject("tcp-window below 4K", "options { tcp-window 4095; };");
    expect_reject("tcp-window above 64M", "options { tcp-window 65M; };");
    expect_reject("tcp-window G suffix", "options { tcp-window 1G; };");
    expect_reject("tcp-window junk", "options { tcp-window big; };");
    expect_reject("tcp-window huge overflow", "options { tcp-window 99999999999999999999M; };");
    expect_reject("udp-bufsize below 512", "options { udp-bufsize 511; };");
    expect_reject("udp-bufsize above 4096", "options { udp-bufsize 4097; };");
    expect_reject("tcp-mss missing semicolon", "options { tcp-mss 1220 };");
    expect_reject("zone-tcp-mss out of range",
                  "zone \"a.example\" { type master; file \"a.zone\"; zone-tcp-mss 100; };");
    expect_reject("zone-tcp-window out of range",
                  "zone \"a.example\" { type master; file \"a.zone\"; zone-tcp-window 1k; };");
    expect_reject("zone-tcp-sndbuf junk",
                  "zone \"a.example\" { type master; file \"a.zone\"; zone-tcp-sndbuf 2MB; };");
    expect_reject("zone-udp-bufsize out of range",
                  "zone \"a.example\" { type master; file \"a.zone\"; zone-udp-bufsize 8192; };");
}

static void test_additional_from_auth(void) {
    printf("[TEST] additional-from-auth at options and zone level...\n");
    static const struct { const char *word; additional_from_auth_t expect; } t[] = {
        { "yes", ADDITIONAL_AUTH_YES },        { "true", ADDITIONAL_AUTH_YES },
        { "in-domain", ADDITIONAL_AUTH_IN_DOMAIN }, { "in-zone", ADDITIONAL_AUTH_IN_DOMAIN },
        { "no", ADDITIONAL_AUTH_NO },          { "false", ADDITIONAL_AUTH_NO },
        { "YES", ADDITIONAL_AUTH_YES },        { "0", ADDITIONAL_AUTH_NO },
        { "In-Domain", ADDITIONAL_AUTH_IN_DOMAIN },
    };
    /* D-02: an unknown value is a configuration error (it used to fall back to yes with a warning) */
    expect_reject("options additional-from-auth bogus", "options { additional-from-auth bogus; };");
    expect_reject("zone additional-from-auth bogus",
                  "zone \"example.com\" { type master; file \"z\"; additional-from-auth bogus; };");
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        char txt[256];
        server_config_t cfg;
        snprintf(txt, sizeof(txt), "options { additional-from-auth %s; };", t[i].word);
        if (parse_ok(txt, &cfg)) { CHECK(cfg.additional_from_auth == t[i].expect); free_server_config_fields(&cfg); }

        snprintf(txt, sizeof(txt),
                 "zone \"example.com\" { type master; file \"z\"; additional-from-auth %s; };", t[i].word);
        if (parse_ok(txt, &cfg)) {
            const zone_config_t *z = first_zone(&cfg);
            CHECK(z != NULL);
            if (z) {
                CHECK(zext(z)->additional_from_auth_specified == true);
                CHECK(zext(z)->additional_from_auth == t[i].expect);
            }
            free_server_config_fields(&cfg);
        }
    }
    server_config_t cfg;
    if (parse_ok("zone \"example.com\" { type master; file \"z\"; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->additional_from_auth_specified == false);
        free_server_config_fields(&cfg);
    }
}

static void test_options_syntax_errors(void) {
    printf("[TEST] options directives: missing value / missing semicolon are rejected...\n");
    static const char *names[] = {
        "ecs-enable", "send-extended-errors", "serve-stale", "rfc10029-mqtype", "tcp-connection-reuse",
        "allow-program-zones", "max-mqtypes", "tcp-idle-timeout", "query-log-max-qps",
        "query-log-buffer-size", "minimal-any-ttl", "wire-cache-max-records", "udp-recvbuf-size",
        "udp-sndbuf-size", "additional-from-auth",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char txt[160];
        /* value present, terminating ';' missing */
        snprintf(txt, sizeof(txt), "options { %s 1024 };", names[i]);
        expect_reject(txt, txt);
        /* value missing entirely */
        snprintf(txt, sizeof(txt), "options { %s; };", names[i]);
        expect_reject(txt, txt);
    }
}

/* ------------------------------------------------------------------------ */
static void test_ecs_and_location_tags(void) {
    printf("[TEST] ecs-tags / location-tags at options and zone level...\n");
    static const char *tags =
        "{ tag \"eu-tier\" { 198.51.100.0/24; 2001:db8::/32; }; tag \"us-tier\" { 203.0.113.0/24; }; "
        "tag \"empty\" { }; };";
    char txt[1024];
    server_config_t cfg;

    snprintf(txt, sizeof(txt), "options { ecs-enable yes; ecs-tags %s location-tags %s };", tags, tags);
    if (parse_ok(txt, &cfg)) {
        CHECK(cfg.ecs_enable == true);
        CHECK(cfg.ecs_tag_count == 3);
        CHECK(cfg.location_tag_count == 3);
        if (cfg.ecs_tag_count == 3) {
            CHECK_STR(cfg.ecs_tags[0].tag, "eu-tier");
            CHECK(cfg.ecs_tags[0].cidr_count == 2);
            if (cfg.ecs_tags[0].cidr_count == 2) {
                CHECK_STR(cfg.ecs_tags[0].cidrs[0].cidr, "198.51.100.0/24");
                CHECK_STR(cfg.ecs_tags[0].cidrs[1].cidr, "2001:db8::/32");
            }
            CHECK_STR(cfg.ecs_tags[1].tag, "us-tier");
            CHECK(cfg.ecs_tags[1].cidr_count == 1);
            CHECK_STR(cfg.ecs_tags[2].tag, "empty");
            CHECK(cfg.ecs_tags[2].cidr_count == 0);
        }
        if (cfg.location_tag_count == 3) CHECK_STR(cfg.location_tags[1].tag, "us-tier");
        free_server_config_fields(&cfg);
    }

    snprintf(txt, sizeof(txt),
             "zone \"example.com\" { type master; file \"z\"; ecs-tags %s location-tags %s };", tags, tags);
    if (parse_ok(txt, &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z != NULL);
        if (z) {
            CHECK(zext(z)->ecs_tag_count == 3);
            CHECK(zext(z)->location_tag_count == 3);
            if (zext(z)->ecs_tag_count == 3) CHECK_STR(zext(z)->ecs_tags[0].tag, "eu-tier");
            if (zext(z)->location_tag_count == 3) CHECK(zext(z)->location_tags[0].cidr_count == 2);
        }
        free_server_config_fields(&cfg);
    }

    /* malformed blocks, both scopes */
    static const char *bad_blocks[] = {
        "ecs-tags \"x\";",                                   /* '{' expected              */
        "ecs-tags { foo \"x\" { }; };",                      /* only 'tag' is allowed     */
        "ecs-tags { tag { }; };",                            /* tag name missing          */
        "ecs-tags { tag \"x\" 10.0.0.0/8; };",               /* '{' expected after name   */
        "ecs-tags { tag \"x\" { 10.0.0.0/8 }; };",           /* ';' after CIDR missing    */
        "ecs-tags { tag \"x\" { { }; }; };",                 /* CIDR must be a string     */
        "ecs-tags { tag \"x\" { 10.0.0.0/8; } };",           /* ';' after tag block       */
        "ecs-tags { tag \"x\" { 10.0.0.0/8; }; }",           /* ';' after ecs-tags block  */
        "location-tags \"x\";",
        "location-tags { tag \"x\" { 10.0.0.0/8; } };",
    };
    for (size_t i = 0; i < sizeof(bad_blocks) / sizeof(bad_blocks[0]); i++) {
        snprintf(txt, sizeof(txt), "options { %s };", bad_blocks[i]);
        expect_reject(txt, txt);
        snprintf(txt, sizeof(txt), "zone \"example.com\" { type master; file \"z\"; %s };", bad_blocks[i]);
        expect_reject(txt, txt);
    }
}

static void test_ecs_trusted_resolvers(void) {
    printf("[TEST] ecs-trusted-resolvers at options and zone level...\n");
    server_config_t cfg;
    if (parse_ok("options { ecs-trusted-resolvers { 192.0.2.53; 2001:db8::53; }; };", &cfg)) {
        CHECK(cfg.ecs_trusted_resolvers_count == 2);
        CHECK(cfg.ecs_trusted_resolvers_parsed != NULL);
        if (cfg.ecs_trusted_resolvers_count == 2) {
            CHECK_STR(cfg.ecs_trusted_resolvers[0], "192.0.2.53");
            CHECK_STR(cfg.ecs_trusted_resolvers[1], "2001:db8::53");
        }
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"example.com\" { type master; file \"z\"; ecs-trusted-resolvers { 10.0.0.0/8; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->ecs_trusted_resolvers_count == 1);
        CHECK(z && zext(z)->ecs_trusted_resolvers_parsed != NULL);
        free_server_config_fields(&cfg);
    }
    expect_reject("options: '{' missing", "options { ecs-trusted-resolvers 192.0.2.1; };");
    expect_reject("options: list unterminated", "options { ecs-trusted-resolvers { 192.0.2.1; ");
    expect_reject("zone: '{' missing",
                  "zone \"example.com\" { type master; file \"z\"; ecs-trusted-resolvers 192.0.2.1; };");
}

/* ------------------------------------------------------------------------ */
/* options { database { } } and the view database options (beta design 7.1, B4a) */
static void test_database_block(void) {
    printf("[TEST] database block and view database options...\n");
    server_config_t cfg;
    if (parse_ok("options { };" ZONE_MIN, &cfg)) {
        CHECK(cfg.database.enabled == false);
        free_server_config_fields(&cfg);
    }

    /* every option with a non-default value */
    static const char *full =
        "options { database { driver sqlite3; database-file \"/var/db/z.sqlite3\"; loader-user \"karidns-db\"; "
        "loader-group \"karidns-db\"; loader-path \"/usr/local/libexec/karidns-dbloader\"; "
        "acl-ceiling { 192.0.2.0/24; }; auto-reload yes; poll-interval 5; coalesce 250; default-ttl 600; "
        "bulk-threshold 40; max-zone-records 5000; max-zone-bytes 64M; db-reload-timeout 45; ingest-threads 4; "
        "loader-threads 8; server-id \"ns1\"; alias-resolver { 192.0.2.53; 2001:db8::53; }; }; };";
    if (parse_ok(full, &cfg)) {
        const database_config_t *d = &cfg.database;
        CHECK(d->enabled);
        CHECK_STR(d->driver, "sqlite3");
        CHECK_STR(d->database_file, "/var/db/z.sqlite3");
        CHECK_STR(d->loader_user, "karidns-db");
        CHECK_STR(d->loader_group, "karidns-db");
        CHECK_STR(db_loader_path(&cfg), "/usr/local/libexec/karidns-dbloader");
        CHECK(d->acl_ceiling_count == 1 && d->acl_ceiling_parsed != NULL);
        CHECK(d->auto_reload && d->poll_interval == 5 && d->coalesce_ms == 250 && d->default_ttl == 600);
        CHECK(d->bulk_threshold == 40 && d->max_zone_records == 5000 && d->max_zone_bytes == 64ull << 20);
        CHECK(d->db_reload_timeout == 45 && d->ingest_threads == 4 && d->loader_threads == 8);
        CHECK_STR(d->server_id, "ns1");
        CHECK(d->alias_resolver_count == 2);
        free_server_config_fields(&cfg);
    }
    /* defaults */
    if (parse_ok("options { database { driver sqlite3; database-file \"/x.db\"; }; };", &cfg)) {
        const database_config_t *d = &cfg.database;
        CHECK(!d->auto_reload && d->poll_interval == 2 && d->coalesce_ms == 1000 && d->default_ttl == 3600);
        CHECK(d->bulk_threshold == 25 && d->max_zone_records == 10000000ull && d->max_zone_bytes == 1ull << 30);
        CHECK(d->db_reload_timeout == 30 && d->ingest_threads == 1 && d->loader_threads == 1);
        CHECK_STR(db_loader_path(&cfg), KARIDNS_DB_DEFAULT_LOADER_PATH);
        free_server_config_fields(&cfg);
    }
#define DBP "options { database { driver sqlite3; database-file \"/x\"; "
    /* ranges */
    expect_reject("poll-interval 0", DBP "poll-interval 0; }; };");
    expect_reject("poll-interval 61", DBP "poll-interval 61; }; };");
    expect_reject("coalesce 10001", DBP "coalesce 10001; }; };");
    expect_reject("default-ttl 0", DBP "default-ttl 0; }; };");
    expect_reject("bulk-threshold 101", DBP "bulk-threshold 101; }; };");
    expect_reject("ingest-threads 17", DBP "ingest-threads 17; }; };");
    expect_reject("loader-threads 0", DBP "loader-threads 0; }; };");
    expect_reject("max-zone-records 1", DBP "max-zone-records 1; }; };");
    expect_reject("max-zone-bytes 100", DBP "max-zone-bytes 100; }; };");
    expect_reject("max-zone-bytes junk", DBP "max-zone-bytes 1X; }; };");
    expect_reject("db-reload-timeout 0", DBP "db-reload-timeout 0; }; };");
    expect_reject("unknown option", DBP "bogus 1; }; };");
    expect_reject("unknown driver", "options { database { driver mysql; }; };");
    expect_reject("no driver", "options { database { database-file \"/x\"; }; };");
    expect_reject("sqlite3 without database-file", "options { database { driver sqlite3; }; };");
    expect_reject("alias-resolver not an address", DBP "alias-resolver { example.test; }; }; };");
    expect_reject("acl-ceiling undefined key", DBP "acl-ceiling { key \"nokey\"; }; }; };");
    expect_reject("block twice", DBP "}; database { driver sqlite3; database-file \"/x\"; }; };");

    /* driver / option consistency (7.1) */
    expect_reject("postgresql with database-file",
                  "options { database { driver postgresql; conninfo-file \"/c\"; database-file \"/x\"; }; };");
    expect_reject("postgresql without conninfo-file", "options { database { driver postgresql; }; };");
    expect_reject("sqlite3 with schema", DBP "schema \"s\"; }; };");
    expect_reject("sqlite3 with conninfo-file", DBP "conninfo-file \"/c\"; }; };");
    expect_reject("view database-schema with sqlite3",
                  DBP "}; }; view \"v\" { database-schema \"s\"; " ZONE_MIN " };");
    expect_reject("view database-file with postgresql",
                  "options { database { driver postgresql; conninfo-file \"/c\"; }; }; view \"v\" { database-file \"/y\"; " ZONE_MIN " };");
    expect_reject("view database option without a block", "view \"v\" { database-file \"/y\"; " ZONE_MIN " };");
    expect_reject("view database none and file",
                  DBP "}; }; view \"v\" { database none; database-file \"/y\"; " ZONE_MIN " };");
    expect_reject("view database junk", DBP "}; }; view \"v\" { database maybe; " ZONE_MIN " };");
    if (parse_ok("options { database { driver sqlite3; }; }; view \"a\" { database-file \"/a.db\"; " ZONE_MIN
                 " }; view \"b\" { database none; };", &cfg)) {
        CHECK_STR(cfg.views->database_file, "/a.db");
        CHECK(cfg.views->next && cfg.views->next->database_none);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { database { driver postgresql; conninfo-file \"/c\"; }; }; view \"a\" { "
                 "database-schema \"pdns_a\"; " ZONE_MIN " };", &cfg)) {
        CHECK_STR(cfg.views->database_schema, "pdns_a");
        free_server_config_fields(&cfg);
    }

    /* paths: UTF-8 passes the lexer byte for byte (no %XX decoding), bad UTF-8 and control characters are errors */
    if (parse_ok("options { database { driver sqlite3; database-file \"/var/db/\xe3\x82\xbe\xe3\x83\xbc\xe3\x83\xb3%41.db\"; }; };", &cfg)) {
        CHECK_STR(cfg.database.database_file, "/var/db/\xe3\x82\xbe\xe3\x83\xbc\xe3\x83\xb3%41.db");
        free_server_config_fields(&cfg);
    }
    expect_reject("invalid UTF-8 (lone continuation byte)", "options { database { driver sqlite3; database-file \"/x\x80.db\"; }; };");
    expect_reject("overlong UTF-8", "options { database { driver sqlite3; database-file \"/x\xc0\xaf.db\"; }; };");
    expect_reject("UTF-8 surrogate", "options { database { driver sqlite3; database-file \"/x\xed\xa0\x80.db\"; }; };");
    expect_reject("control character", "options { database { driver sqlite3; database-file \"/x\ty.db\"; }; };");
    expect_reject("C1 control character", "options { database { driver sqlite3; database-file \"/x\xc2\x85y.db\"; }; };");
    expect_reject("empty path", "options { database { driver sqlite3; database-file \"\"; }; };");
#undef DBP
}

static void test_dnstap_block(void) {
    printf("[TEST] dnstap block (options-level and top-level)...\n");
    server_config_t cfg;
    static const char *body =
        "{ socket \"/var/run/dnstap.sock\"; identity \"ns1\"; version \"KariDNS test\"; queue-size 8192; "
        "auth-query yes; auth-response true; require-connect 1; some-future-option x; };";
    char txt[512];

    snprintf(txt, sizeof(txt), "options { dnstap %s };", body);
    if (parse_ok(txt, &cfg)) {
        CHECK(cfg.dnstap.enabled == true);
        CHECK_STR(cfg.dnstap.socket_path, "/var/run/dnstap.sock");
        CHECK_STR(cfg.dnstap.identity, "ns1");
        CHECK_STR(cfg.dnstap.version, "KariDNS test");
        CHECK(cfg.dnstap.queue_size == 8192);
        CHECK(cfg.dnstap.log_auth_query == true);
        CHECK(cfg.dnstap.log_auth_response == true);
        CHECK(cfg.dnstap.require_connect == true);
        free_server_config_fields(&cfg);
    }
    snprintf(txt, sizeof(txt), "dnstap %s", body);
    if (parse_ok(txt, &cfg)) {
        CHECK(cfg.dnstap.enabled == true);
        CHECK_STR(cfg.dnstap.identity, "ns1");
        CHECK(cfg.dnstap.queue_size == 8192);
        free_server_config_fields(&cfg);
    }
    /* alias spellings and the "off" values */
    if (parse_ok("dnstap { socket-path \"/s\"; queue_size 128; log-queries no; log-responses false; "
                 "require-connect no; };", &cfg)) {
        CHECK_STR(cfg.dnstap.socket_path, "/s");
        CHECK(cfg.dnstap.queue_size == 128);
        CHECK(cfg.dnstap.log_auth_query == false);
        CHECK(cfg.dnstap.log_auth_response == false);
        CHECK(cfg.dnstap.require_connect == false);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("dnstap { log-queries true; log-responses 1; };", &cfg)) {
        CHECK(cfg.dnstap.log_auth_query == true);
        CHECK(cfg.dnstap.log_auth_response == true);
        free_server_config_fields(&cfg);
    }
    /* an empty block still enables dnstap with the documented default queue size */
    if (parse_ok("dnstap { };", &cfg)) {
        CHECK(cfg.dnstap.enabled == true);
        CHECK(cfg.dnstap.queue_size == 4096);
        CHECK(cfg.dnstap.socket_path == NULL);
        /* neither message type given: both queries and responses are logged */
        CHECK(cfg.dnstap.log_auth_query == true);
        CHECK(cfg.dnstap.log_auth_response == true);
        free_server_config_fields(&cfg);
    }
    /* only one type given: the other one is off */
    if (parse_ok("dnstap { socket \"/s\"; log-queries yes; };", &cfg)) {
        CHECK(cfg.dnstap.log_auth_query == true);
        CHECK(cfg.dnstap.log_auth_response == false);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("dnstap { socket \"/s\"; auth-response yes; };", &cfg)) {
        CHECK(cfg.dnstap.log_auth_query == false);
        CHECK(cfg.dnstap.log_auth_response == true);
        free_server_config_fields(&cfg);
    }
    /* a repeated property replaces (and frees) the earlier value */
    if (parse_ok("dnstap { identity \"a\"; identity \"b\"; socket \"/x\"; socket \"/y\"; version \"1\"; version \"2\"; };", &cfg)) {
        CHECK_STR(cfg.dnstap.identity, "b");
        CHECK_STR(cfg.dnstap.socket_path, "/y");
        CHECK_STR(cfg.dnstap.version, "2");
        free_server_config_fields(&cfg);
    }

    expect_reject("no '{'", "dnstap \"x\";");
    expect_reject("value is not a string", "dnstap { socket; };");
    expect_reject("';' after value missing", "dnstap { socket \"x\" };");
    expect_reject("';' after block missing (top level)", "dnstap { socket \"x\"; }");
    expect_reject("';' after block missing (options)", "options { dnstap { socket \"x\"; } };");
    expect_reject("property is not a string", "dnstap { { }; };");
}

/* ------------------------------------------------------------------------ */
static void test_zone_types_and_files(void) {
    printf("[TEST] zone type / file-format / tsig-key / catalog-zone / masters...\n");
    server_config_t cfg;

    static const struct { const char *in; const char *stored; } types[] = {
        { "master", "master" }, { "primary", "master" }, { "PRIMARY", "master" },
        { "slave", "slave" },   { "secondary", "slave" }, { "forward", "forward" },
        { "program", "program" },
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        char txt[256];
        snprintf(txt, sizeof(txt), "zone \"example.com\" { type %s; file \"z\"; };", types[i].in);
        if (parse_ok(txt, &cfg)) {
            const zone_config_t *z = first_zone(&cfg);
            CHECK(z != NULL);
            if (z) {
                CHECK_STR(z->type, types[i].stored);
                CHECK_STR(z->domain, "example.com.");        /* trailing dot is normalised */
            }
            free_server_config_fields(&cfg);
        }
    }
    expect_reject("unknown zone type", "zone \"example.com\" { type hint; file \"z\"; };");
    expect_reject("type value missing", "zone \"example.com\" { type; };");
    expect_reject("';' missing after type", "zone \"example.com\" { type master };");
    expect_reject("zone name is not a string", "zone { type master; };");
    expect_reject("'{' missing after zone name", "zone \"example.com\" type master;");
    expect_reject("non-string directive inside zone", "zone \"example.com\" { ; };");

    /* file-format */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; file-format bind; };", &cfg)) {
        CHECK_STR(zext(first_zone(&cfg))->file_format, "bind"); free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; file-format TinyDNS; };", &cfg)) {
        CHECK_STR(zext(first_zone(&cfg))->file_format, "TinyDNS"); free_server_config_fields(&cfg);
    }
    expect_reject("file-format yaml", "zone \"a.test\" { type master; file \"z\"; file-format yaml; };");

    /* catalog-zone, notify-source, file */
    if (parse_ok("zone \"cat.test\" { type master; file \"cat.zone\"; catalog-zone yes; notify-source 192.0.2.10; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->is_catalog == true);
        if (z) { CHECK_STR(zext(z)->notify_source, "192.0.2.10"); CHECK_STR(z->file, "cat.zone"); }
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"cat.test\" { type master; file \"cat.zone\"; catalog-zone no; };", &cfg)) {
        CHECK(first_zone(&cfg)->is_catalog == false); free_server_config_fields(&cfg);
    }

    /* masters / also-notify with optional ports */
    if (parse_ok("zone \"s.test\" { type slave; file \"s.zone\"; masters { 192.0.2.1 port 5353; 198.51.100.1; }; "
                 "also-notify { 192.0.2.99 port 5354; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->masters_count == 2 && zext(z)->masters_parsed != NULL);
        if (z && zext(z)->masters_count == 2) {
            CHECK_STR(zext(z)->masters[0].ip, "192.0.2.1"); CHECK(zext(z)->masters[0].port == 5353);
            CHECK_STR(zext(z)->masters[1].ip, "198.51.100.1"); CHECK(zext(z)->masters[1].port == 53);
        }
        CHECK(z && zext(z)->also_notify_count == 1 && zext(z)->also_notify[0].port == 5354);
        free_server_config_fields(&cfg);
    }
    expect_reject("port 0", "zone \"s.test\" { type slave; masters { 192.0.2.1 port 0; }; };");
    expect_reject("port > 65535", "zone \"s.test\" { type slave; masters { 192.0.2.1 port 70000; }; };");
    expect_reject("port not numeric", "zone \"s.test\" { type slave; masters { 192.0.2.1 port dns; }; };");
    expect_reject("port value missing", "zone \"s.test\" { type slave; masters { 192.0.2.1 port; }; };");
    expect_reject("';' missing after address", "zone \"s.test\" { type slave; masters { 192.0.2.1 }; };");
    expect_reject("masters without braces", "zone \"s.test\" { type slave; masters 192.0.2.1; };");
    expect_reject("masters list not closed with ';'", "zone \"s.test\" { type slave; masters { 192.0.2.1; } };");
    expect_reject("non-string in address list", "zone \"s.test\" { type slave; masters { { }; }; };");

    /* tsig-key must refer to a defined key */
    char txt[512];
    snprintf(txt, sizeof(txt), "key \"k1\" { algorithm hmac-sha256; secret \"%s\"; };"
             "zone \"x.test\" { type slave; file \"z\"; masters { 192.0.2.1; }; tsig-key k1; };", SECRET_OK);
    if (parse_ok(txt, &cfg)) { CHECK_STR(zext(first_zone(&cfg))->tsig_key, "k1"); free_server_config_fields(&cfg); }
    expect_reject("undefined tsig-key", "zone \"x.test\" { type slave; file \"z\"; tsig-key nokey; };");
}

static void test_zone_program_and_forward(void) {
    printf("[TEST] program zones (program-*), forward zones, program-user inheritance...\n");
    server_config_t cfg;
    if (parse_ok("options { user \"nobody\"; allow-program-zones yes; };"
                 "zone \"dyn.example\" { type program; program \"/usr/local/bin/backend\"; "
                 "program-args { \"--verbose\"; \"zone=dyn\"; }; program-user \"svc\"; "
                 "program-timeout 750; program-max-failures 3; };"
                 "zone \"dyn2.example\" { type program; program \"/bin/true\"; };", &cfg)) {
        CHECK(cfg.allow_program_zones == true);
        CHECK_STR(cfg.user, "nobody");
        const zone_config_t *z1 = first_zone(&cfg);
        CHECK(z1 != NULL);
        if (z1) {
            CHECK_STR(zext(z1)->program_path, "/usr/local/bin/backend");
            CHECK(zext(z1)->program_args_count == 2);
            if (zext(z1)->program_args_count == 2) {
                CHECK_STR(zext(z1)->program_args[0], "--verbose");
                CHECK_STR(zext(z1)->program_args[1], "zone=dyn");
            }
            CHECK_STR(zext(z1)->program_user, "svc");
            CHECK(zext(z1)->program_timeout_ms == 750);
            CHECK(zext(z1)->program_max_failures == 3);
            const zone_config_t *z2 = z1->next;
            CHECK(z2 != NULL);
            if (z2) {
                CHECK_STR(zext(z2)->program_path, "/bin/true");
                CHECK_STR(zext(z2)->program_user, "nobody");   /* inherited from options { user } */
            }
        }
        free_server_config_fields(&cfg);
    }
    expect_reject("program path missing", "zone \"d.test\" { type program; program; };");
    expect_reject("program ';' missing", "zone \"d.test\" { type program; program \"/bin/x\" };");
    expect_reject("program-args without braces", "zone \"d.test\" { type program; program-args foo; };");
    expect_reject("program-user missing", "zone \"d.test\" { type program; program-user; };");
    expect_reject("program-user ';' missing", "zone \"d.test\" { type program; program-user x };");
    expect_reject("program-timeout value missing", "zone \"d.test\" { type program; program-timeout; };");
    expect_reject("program-timeout ';' missing", "zone \"d.test\" { type program; program-timeout 5 };");
    expect_reject("program-max-failures value missing", "zone \"d.test\" { type program; program-max-failures; };");
    expect_reject("program-max-failures ';' missing", "zone \"d.test\" { type program; program-max-failures 5 };");

    if (parse_ok("zone \"f.example\" { type forward; forwarders { 192.0.2.53; 198.51.100.53 port 5353; }; "
                 "forward-timeout 1500; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->forwarders_count == 2);
        if (z && zext(z)->forwarders_count == 2) {
            CHECK_STR(zext(z)->forwarders[0].ip, "192.0.2.53"); CHECK(zext(z)->forwarders[0].port == 53);
            CHECK(zext(z)->forwarders[1].port == 5353);
        }
        CHECK(z && zext(z)->forward_timeout_ms == 1500);
        free_server_config_fields(&cfg);
    }
    expect_reject("forwarders without braces", "zone \"f.test\" { type forward; forwarders 192.0.2.53; };");
    expect_reject("forward-timeout value missing", "zone \"f.test\" { type forward; forward-timeout; };");
    expect_reject("forward-timeout ';' missing", "zone \"f.test\" { type forward; forward-timeout 5 };");
}

static void test_zone_rate_limit(void) {
    printf("[TEST] rate-limit block (per zone)...\n");
    server_config_t cfg;
    if (parse_ok("zone \"r.test\" { type master; file \"z\"; rate-limit { responses-per-second 20; "
                 "nxdomains-per-second 5; errors-per-second 7; window 30; slip 4; log-only yes; early-drop true; "
                 "exempt-clients { 192.0.2.0/24; 10.0.0.1 port 5300; }; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z != NULL);
        if (z) {
            const rate_limit_config_t *r = &zext(z)->rrl;
            CHECK(r->configured == true);
            CHECK(r->responses_per_second == 20);
            CHECK(r->nodata_per_second == 20);            /* not set explicitly: follows responses-per-second */
            CHECK(r->nodata_per_second_set == false);
            CHECK(r->nxdomains_per_second == 5);
            CHECK(r->errors_per_second == 7);
            CHECK(r->window_seconds == 30);
            CHECK(r->slip == 4);
            CHECK(r->log_only == true);
            CHECK(r->early_drop == true);
            CHECK(r->exempt_clients_count == 2);
            CHECK(r->exempt_clients_parsed != NULL);
        }
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { rate-limit { responses-per-second 50; nodata-per-second 9; log-only no; "
                 "early-drop 1; }; };", &cfg)) {
        CHECK(cfg.rrl.responses_per_second == 50);
        CHECK(cfg.rrl.nodata_per_second == 9);
        CHECK(cfg.rrl.nodata_per_second_set == true);
        CHECK(cfg.rrl.log_only == false);
        CHECK(cfg.rrl.early_drop == true);
        free_server_config_fields(&cfg);
    }
    /* invalid numbers are ignored (warning), the documented defaults stay: window 15 s, slip 2 */
    if (parse_ok("options { rate-limit { window 0; slip -1; nodata-per-second x; some-future-knob 1; }; };", &cfg)) {
        CHECK(cfg.rrl.window_seconds == 15);
        CHECK(cfg.rrl.slip == 2);
        CHECK(cfg.rrl.nodata_per_second_set == false);
        free_server_config_fields(&cfg);
    }
    /* D-05: BIND options: prefix lengths, referrals-per-second (defaults to responses-per-second),
     * all-per-second; qps-scale / min-table-size / max-table-size are accepted but have no effect */
    if (parse_ok("options { rate-limit { responses-per-second 8; all-per-second 30; ipv4-prefix-length 32; "
                 "ipv6-prefix-length 64; qps-scale 250; min-table-size 500; max-table-size 20000; }; };", &cfg)) {
        CHECK(cfg.rrl.referrals_per_second == 8);
        CHECK(cfg.rrl.referrals_per_second_set == false);
        CHECK(cfg.rrl.all_per_second == 30);
        CHECK(cfg.rrl.ipv4_prefix_length == 32 && cfg.rrl.ipv4_prefix_length_set);
        CHECK(cfg.rrl.ipv6_prefix_length == 64 && cfg.rrl.ipv6_prefix_length_set);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { rate-limit { responses-per-second 8; referrals-per-second 3; ipv4-prefix-length 33; "
                 "ipv6-prefix-length 129; }; };", &cfg)) {
        CHECK(cfg.rrl.referrals_per_second == 3 && cfg.rrl.referrals_per_second_set);
        CHECK(cfg.rrl.ipv4_prefix_length == 24 && !cfg.rrl.ipv4_prefix_length_set);   /* out of range: ignored */
        CHECK(cfg.rrl.ipv6_prefix_length == 56 && !cfg.rrl.ipv6_prefix_length_set);
        free_server_config_fields(&cfg);
    }
    expect_reject("rate-limit without braces", "options { rate-limit yes; };");
    expect_reject("rate-limit value missing", "options { rate-limit { window; }; };");
    expect_reject("rate-limit ';' missing after value", "options { rate-limit { window 5 }; };");
    expect_reject("rate-limit ';' missing after block", "options { rate-limit { window 5; } };");
    expect_reject("rate-limit non-string key", "options { rate-limit { { }; }; };");
    expect_reject("exempt-clients without braces", "options { rate-limit { exempt-clients 1.2.3.4; }; };");
}

/* ------------------------------------------------------------------------ */
static void test_acl_lists(void) {
    printf("[TEST] allow-transfer / allow-update ACL lists incl. negation...\n");
    server_config_t cfg;
    char txt[1024];
    static const char *keydef_tmpl = "key \"k1\" { algorithm hmac-sha256; secret \"%s\"; };";
    char keydef[256];
    snprintf(keydef, sizeof(keydef), keydef_tmpl, SECRET_OK);

    /* allow-transfer: addresses stay in the ACL, `key` entries go to the zone's TSIG key list */
    snprintf(txt, sizeof(txt), "%s zone \"a.test\" { type master; file \"z\"; "
             "allow-transfer { 192.0.2.1; key k1; 198.51.100.0/24; }; };", keydef);
    if (parse_ok(txt, &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_transfer_count == 2);
        if (z && zext(z)->allow_transfer_count == 2) {
            CHECK_STR(zext(z)->allow_transfer[0], "192.0.2.1");
            CHECK_STR(zext(z)->allow_transfer[1], "198.51.100.0/24");
        }
        CHECK(z && zext(z)->tsig_keys_count == 1);
        if (z && zext(z)->tsig_keys_count == 1) CHECK_STR(zext(z)->tsig_keys[0], "k1");
        CHECK(z && zext(z)->allow_transfer_parsed != NULL);
        free_server_config_fields(&cfg);
    }
    /* allow-update: a key is kept in the list itself */
    snprintf(txt, sizeof(txt), "%s zone \"a.test\" { type master; file \"z\"; "
             "allow-update { 192.0.2.0/24; key k1; }; };", keydef);
    if (parse_ok(txt, &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_update_count == 2);
        if (z && zext(z)->allow_update_count == 2) { CHECK_STR(zext(z)->allow_update[0], "192.0.2.0/24"); CHECK_STR(zext(z)->allow_update[1], "k1"); }
        free_server_config_fields(&cfg);
    }
    /* single negated entry */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-transfer { ! 192.0.2.9; 192.0.2.0/24; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_transfer_count == 2);
        if (z && zext(z)->allow_transfer_count == 2) { CHECK_STR(zext(z)->allow_transfer[0], "!192.0.2.9"); CHECK_STR(zext(z)->allow_transfer[1], "192.0.2.0/24"); }
        free_server_config_fields(&cfg);
    }
    /* negated block: every member is negated, `any` disappears (BIND: !{ x; any; } == !x) */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-transfer { ! { 10.0.0.0/8; any; }; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_transfer_count == 1);
        if (z && zext(z)->allow_transfer_count == 1) CHECK_STR(zext(z)->allow_transfer[0], "!10.0.0.0/8");
        free_server_config_fields(&cfg);
    }
    /* double negation inside a negated block cancels: !{ !x; } == x */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-transfer { ! { !192.0.2.1; }; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_transfer_count == 1);
        if (z && zext(z)->allow_transfer_count == 1) CHECK_STR(zext(z)->allow_transfer[0], "192.0.2.1");
        free_server_config_fields(&cfg);
    }
    /* `any` at top level is an ordinary entry */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-update { any; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_update_count == 1 && strcmp(zext(z)->allow_update[0], "any") == 0);
        free_server_config_fields(&cfg);
    }

    expect_reject("allow-transfer without braces", "zone \"a.test\" { type master; allow-transfer any; };");
    expect_reject("allow-transfer unterminated", "zone \"a.test\" { type master; allow-transfer { 1.2.3.4; ");
    expect_reject("key without name", "zone \"a.test\" { type master; allow-transfer { key ; }; };");
    expect_reject("negated block without ';'", "zone \"a.test\" { type master; allow-transfer { ! { 10.0.0.0/8; } }; };");
    expect_reject("'!' at end of list", "zone \"a.test\" { type master; allow-transfer { ! }; };");
    expect_reject("undefined allow-transfer key", "zone \"a.test\" { type master; allow-transfer { key nokey; }; };");
}

/* ------------------------------------------------------------------------ */
static void test_tsig_key_blocks(void) {
    printf("[TEST] key { } blocks: algorithms, secrets, structure errors, duplicates...\n");
    server_config_t cfg;
    char txt[1024];

    static const char *algs[] = {
        "hmac-md5", "hmac-md5.sig-alg.reg.int", "hmac-sha1", "hmac-sha224",
        "hmac-sha256", "hmac-sha384", "hmac-sha512",
    };
    for (size_t i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        snprintf(txt, sizeof(txt), "key \"k\" { algorithm %s; secret \"%s\"; };", algs[i], SECRET_OK);
        if (parse_ok(txt, &cfg)) {
            CHECK(cfg.keys != NULL);
            if (cfg.keys) {
                CHECK_STR(cfg.keys->name, "k");
                CHECK_STR(cfg.keys->algorithm, algs[i]);
                CHECK_STR(cfg.keys->secret, SECRET_OK);
            }
            free_server_config_fields(&cfg);
        }
    }

    /* The secret decodes to 32 bytes; expected bytes computed independently with Python base64. */
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; secret \"%s\"; };", SECRET_OK);
    if (parse_ok(txt, &cfg)) {
        static const uint8_t first8[8] = { 0x93, 0xb7, 0xbc, 0xbd, 0x6f, 0x1f, 0xd1, 0x6e };
        CHECK(cfg.keys && cfg.keys->secret_decoded_len == 32);
        if (cfg.keys) {
            CHECK(memcmp(cfg.keys->secret_decoded, first8, 8) == 0);
            CHECK(cfg.keys->secret_decoded[31] == 0x45);
        }
        free_server_config_fields(&cfg);
    }

    /* two keys are kept in definition order */
    snprintf(txt, sizeof(txt), "key \"a\" { algorithm hmac-sha256; secret \"%s\"; };"
             "key \"b\" { algorithm hmac-sha512; secret \"%s\"; };", SECRET_OK, SECRET_OK);
    if (parse_ok(txt, &cfg)) {
        CHECK(cfg.keys && cfg.keys->next);
        if (cfg.keys && cfg.keys->next) { CHECK_STR(cfg.keys->name, "a"); CHECK_STR(cfg.keys->next->name, "b"); }
        free_server_config_fields(&cfg);
    }

    /* an unknown property inside key{} is skipped, the key stays usable */
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; comment { x; }; secret \"%s\"; };", SECRET_OK);
    if (parse_ok(txt, &cfg)) { CHECK(cfg.keys && cfg.keys->secret_decoded_len == 32); free_server_config_fields(&cfg); }

    /* rejections */
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha3; secret \"%s\"; };", SECRET_OK);
    expect_reject("unsupported algorithm", txt);
    expect_reject("empty secret", "key \"k\" { algorithm hmac-sha256; secret \"\"; };");
    {
        char longsecret[512];
        memset(longsecret, 'A', 400);          /* 400 base64 chars > 256 decoded bytes */
        longsecret[400] = '\0';
        snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; secret \"%s\"; };", longsecret);
        expect_reject("secret too long", txt);
    }
    snprintf(txt, sizeof(txt), "key \"Dup\" { algorithm hmac-sha256; secret \"%s\"; };"
             "key \"dup\" { algorithm hmac-sha256; secret \"%s\"; };", SECRET_OK, SECRET_OK);
    expect_reject("duplicate key (case-insensitive)", txt);

    expect_reject("key name missing", "key { algorithm hmac-sha256; };");
    expect_reject("'{' missing", "key \"k\" \"x\";");
    expect_reject("property is not a string", "key \"k\" { ; };");
    expect_reject("algorithm value missing", "key \"k\" { algorithm; };");
    expect_reject("algorithm ';' missing", "key \"k\" { algorithm hmac-sha256 };");
    expect_reject("secret ';' missing", "key \"k\" { secret \"QUJD\" };");
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; secret \"%s\"; }", SECRET_OK);
    expect_reject("final ';' missing", txt);
}

static void test_control_channel(void) {
    printf("[TEST] control-channel block...\n");
    server_config_t cfg;
    char txt[1024];
    snprintf(txt, sizeof(txt),
             "control-channel { algorithm hmac-sha256; secret \"%s\"; socket \"/var/run/karidns.sock\"; };", SECRET_OK);
    if (parse_ok(txt, &cfg)) {
        CHECK(cfg.control.enabled == true);
        CHECK_STR(cfg.control.algorithm, "hmac-sha256");
        CHECK_STR(cfg.control.socket_path, "/var/run/karidns.sock");
        CHECK(cfg.control.secret_decoded_len == 32);
        free_server_config_fields(&cfg);
    }
    snprintf(txt, sizeof(txt), "control-channel { socket-path \"/a\"; socket-path \"/b\"; secret \"%s\"; secret \"%s\"; "
             "algorithm hmac-sha1; algorithm hmac-sha512; };", SECRET_OK, SECRET_OK);
    if (parse_ok(txt, &cfg)) {    /* repeated properties replace the earlier value */
        CHECK_STR(cfg.control.socket_path, "/b");
        CHECK_STR(cfg.control.algorithm, "hmac-sha512");
        free_server_config_fields(&cfg);
    }
    if (parse_ok("control-channel { };", &cfg)) { CHECK(cfg.control.enabled == true); free_server_config_fields(&cfg); }
    if (parse_ok("control-channel { future-option { a; }; };", &cfg)) { CHECK(cfg.control.enabled == true); free_server_config_fields(&cfg); }

    expect_reject("unsupported algorithm", "control-channel { algorithm hmac-sha3; };");
    /* D17-3: control-channel is a top-level statement; inside options { } it used to be skipped silently */
    snprintf(txt, sizeof(txt), "options { port 5353; control-channel { algorithm hmac-sha256; secret \"%s\"; }; };", SECRET_OK);
    expect_reject("control-channel inside options", txt);
    snprintf(txt, sizeof(txt), "options { port 5353; }; control-channel { algorithm hmac-sha256; secret \"%s\"; };", SECRET_OK);
    if (parse_ok(txt, &cfg)) { CHECK(cfg.control.enabled == true); CHECK(cfg.port == 5353); free_server_config_fields(&cfg); }
    expect_reject("empty secret", "control-channel { secret \"\"; };");
    {
        char longsecret[512];
        memset(longsecret, 'A', 400);
        longsecret[400] = '\0';
        snprintf(txt, sizeof(txt), "control-channel { secret \"%s\"; };", longsecret);
        expect_reject("secret too long", txt);
    }
    expect_reject("'{' missing", "control-channel \"x\";");
    expect_reject("property is not a string", "control-channel { ; };");
    expect_reject("value missing", "control-channel { socket; };");
    expect_reject("value ';' missing", "control-channel { socket \"/x\" };");
    expect_reject("final ';' missing", "control-channel { socket \"/x\"; }");
}

/* ------------------------------------------------------------------------ */
static const log_channel_t *find_channel(const server_config_t *cfg, const char *name) {
    for (const log_channel_t *c = cfg->logging.channels; c; c = c->next)
        if (c->name && strcmp(c->name, name) == 0) return c;
    return NULL;
}

static void test_logging_channels(void) {
    printf("[TEST] logging { channel / category } incl. size suffixes...\n");
    server_config_t cfg;
    if (parse_ok("options { query-log-max-qps 300; };"
                 "logging {"
                 "  channel \"q\" { file \"/var/log/q.log\" versions 5 size 10m suffix timestamp; "
                 "                 print-time yes; print-category yes; print-severity no; max-qps 100; };"
                 "  channel \"r\" { file \"/var/log/r.log\" size 512k; print-severity yes; };"
                 "  channel \"g\" { file \"/var/log/g.log\" size 2G; };"
                 "  channel \"b\" { file \"/var/log/b.log\" size 3MB; };"
                 "  channel \"n\" { file \"/var/log/n.log\" size 4096; };"
                 "  category queries { q; }; category responses { r; }; category default { q; };"
                 "};", &cfg)) {
        const log_channel_t *q = find_channel(&cfg, "q"), *r = find_channel(&cfg, "r");
        const log_channel_t *g = find_channel(&cfg, "g"), *b = find_channel(&cfg, "b"), *n = find_channel(&cfg, "n");
        CHECK(q && r && g && b && n);
        if (q) {
            CHECK_STR(q->file_path, "/var/log/q.log");
            CHECK(q->versions == 5);
            CHECK(q->size_limit == 10ULL * 1024 * 1024);
            CHECK(q->suffix_timestamp == true);
            CHECK(q->print_time == true && q->print_category == true && q->print_severity == false);
            CHECK(q->max_qps == 100 && q->max_qps_specified == true);
        }
        if (r) {
            CHECK(r->size_limit == 512ULL * 1024);
            CHECK(r->print_severity == true && r->print_time == false);
            CHECK(r->max_qps_specified == false);
            CHECK(r->max_qps == 300);                 /* inherits options { query-log-max-qps } */
        }
        if (g) CHECK(g->size_limit == 2ULL * 1024 * 1024 * 1024);
        if (b) CHECK(b->size_limit == 3ULL * 1024 * 1024);   /* trailing 'B' is accepted after a unit */
        if (n) CHECK(n->size_limit == 4096);
        CHECK(cfg.logging.queries_channel == q);
        CHECK(cfg.logging.responses_channel == r);
        free_server_config_fields(&cfg);
    }
    /* invalid size / versions / max-qps values are reported and ignored; the config is still accepted */
    if (parse_ok("logging { channel \"x\" { file \"/x\" size -5; }; channel \"y\" { file \"/y\" size abc; }; "
                 "channel \"z\" { file \"/z\" versions -2 size k; }; "
                 "channel \"m\" { file \"/m\"; max-qps abc; }; };", &cfg)) {
        const log_channel_t *x = find_channel(&cfg, "x"), *y = find_channel(&cfg, "y");
        const log_channel_t *z = find_channel(&cfg, "z"), *m = find_channel(&cfg, "m");
        CHECK(x && x->size_limit == 0);
        CHECK(y && y->size_limit == 0);
        CHECK(z && z->size_limit == 0 && z->versions == 0);
        CHECK(m && m->max_qps_specified == false);
        free_server_config_fields(&cfg);
    }
    /* unknown statements inside logging / channel are skipped */
    if (parse_ok("logging { severity dynamic; channel \"c\" { syslog daemon; file \"/c\"; }; };", &cfg)) {
        CHECK(find_channel(&cfg, "c") != NULL);
        free_server_config_fields(&cfg);
    }

    expect_reject("queries category -> undefined channel",
                  "logging { channel \"a\" { file \"/a\"; }; category queries { nope; }; };");
    expect_reject("responses category -> undefined channel",
                  "logging { channel \"a\" { file \"/a\"; }; category responses { nope; }; };");
    expect_reject("logging without braces", "logging \"x\";");
    expect_reject("channel name missing", "logging { channel { file \"/a\"; }; };");
    expect_reject("channel '{' missing", "logging { channel \"a\" file \"/a\"; };");
    expect_reject("channel option is not a string", "logging { channel \"a\" { ; }; };");
    expect_reject("channel file path missing", "logging { channel \"a\" { file; }; };");
    expect_reject("category name missing", "logging { category { a; }; };");
    expect_reject("directive is not a string", "logging { ; };");
    expect_reject("logging final ';' missing", "logging { channel \"a\" { file \"/a\"; }; }");
}

/* ------------------------------------------------------------------------ */
static void test_structure_and_validation(void) {
    printf("[TEST] top-level structure and post-parse validation...\n");
    server_config_t cfg;

    expect_reject("top-level zone mixed with view", "zone \"a.test\" { type master; file \"z\"; };"
                  "view \"v\" { match-clients { any; }; zone \"b.test\" { type master; file \"z\"; }; };");
    expect_reject("view first, then top-level zone", "view \"v\" { match-clients { any; }; };"
                  "zone \"b.test\" { type master; file \"z\"; };");
    /* match-clients is an address match list only: a key entry would never match */
    expect_reject("key in match-clients", "key \"k1\" { algorithm hmac-sha256; secret \"c2VjcmV0\"; };"
                  "view \"v\" { match-clients { key \"k1\"; }; zone \"b.test\" { type master; file \"z\"; }; };");
    expect_reject("key after an address in match-clients", "view \"v\" { match-clients { 192.0.2.0/24; key k1; }; };");

    if (parse_ok("acl \"trusted\" { 192.0.2.0/24; }; statistics-channels { inet 127.0.0.1; };"
                 "options { port 5300; }; " ZONE_MIN, &cfg)) {
        CHECK(cfg.port == 5300);
        CHECK(first_zone(&cfg) != NULL);
        CHECK(cfg.views && strcmp(cfg.views->name, "__default__") == 0);
        CHECK(cfg.zones == NULL && cfg.views->zones != NULL); /* S6a: ゾーン構造体の複製のフラットリストは無い */
        free_server_config_fields(&cfg);
    }
    if (parse_ok("view \"internal\" { match-clients { 10.0.0.0/8; }; " ZONE_MIN " };"
                 "view \"external\" { match-clients { any; }; " ZONE_MIN " };", &cfg)) {
        CHECK(cfg.views && cfg.views->next);
        if (cfg.views && cfg.views->next) {
            CHECK_STR(cfg.views->name, "internal");
            CHECK(cfg.views->match_clients_count == 1);
            CHECK_STR(cfg.views->next->name, "external");
        }
        free_server_config_fields(&cfg);
    }
    if (parse_ok("# comment\n// c++ comment\n/* block\n comment */ options { port 5301; };\n", &cfg)) {
        CHECK(cfg.port == 5301);
        free_server_config_fields(&cfg);
    }
    expect_reject("options without braces", "options 53;");
    expect_reject("unterminated options", "options { port 53; ");
    expect_reject("view name missing", "view { };");

    /* zone_db_entry_t keeps the view name in KARIDNS_VIEW_NAME_MAX bytes: a longer name would be cut and the view's
     * zones would lose their settings, so it is rejected; the longest name that fits is accepted */
    {
        char name[KARIDNS_VIEW_NAME_MAX + 1], txt[512];
        memset(name, 'v', KARIDNS_VIEW_NAME_MAX - 1);
        name[KARIDNS_VIEW_NAME_MAX - 1] = '\0';
        snprintf(txt, sizeof(txt), "view \"%s\" { match-clients { any; }; " ZONE_MIN " };", name);
        if (parse_ok(txt, &cfg)) {
            CHECK(cfg.views && strlen(cfg.views->name) == KARIDNS_VIEW_NAME_MAX - 1);
            free_server_config_fields(&cfg);
        }
        name[KARIDNS_VIEW_NAME_MAX - 1] = 'v';
        name[KARIDNS_VIEW_NAME_MAX] = '\0';
        snprintf(txt, sizeof(txt), "view \"%s\" { match-clients { any; }; " ZONE_MIN " };", name);
        expect_reject("view name longer than KARIDNS_VIEW_NAME_MAX - 1", txt);
    }
}

/* ------------------------------------------------------------------------ */
static void test_config_cidr_matching(void) {
    printf("[TEST] config parser: match_cidr helper coverage (IPv4/IPv6, boundary masks, invalid prefixes)...\n");

    /* 1. NULL and keyword checks */
    CHECK(match_cidr(NULL, "192.0.2.0/24") == false);
    CHECK(match_cidr("192.0.2.1", NULL) == false);
    CHECK(match_cidr("192.0.2.1", "any") == true);
    CHECK(match_cidr("2001:db8::1", "any;") == true);

    /* 2. IPv4 matching and prefix edge cases */
    CHECK(match_cidr("192.0.2.1", "192.0.2.0/24") == true);
    CHECK(match_cidr("192.0.3.1", "192.0.2.0/24") == false);
    CHECK(match_cidr("192.0.2.1", "192.0.2.1/32") == true);
    CHECK(match_cidr("192.0.2.2", "192.0.2.1/32") == false);
    CHECK(match_cidr("10.0.0.1", "0.0.0.0/0") == true);
    CHECK(match_cidr("192.0.2.1", "192.0.2.1") == true); /* implicit /32 */

    /* 3. IPv4 invalid prefixes */
    CHECK(match_cidr("192.0.2.1", "192.0.2.0/33") == false);
    CHECK(match_cidr("192.0.2.1", "192.0.2.0/-1") == false);
    CHECK(match_cidr("192.0.2.1", "192.0.2.0/abc") == false);
    CHECK(match_cidr("192.0.2.1", "192.0.2.0/") == false);

    /* 4. IPv6 matching and prefix edge cases */
    CHECK(match_cidr("2001:db8::1", "2001:db8::/32") == true);
    CHECK(match_cidr("2001:db9::1", "2001:db8::/32") == false);
    CHECK(match_cidr("2001:db8::1", "2001:db8::1/128") == true);
    CHECK(match_cidr("2001:db8::2", "2001:db8::1/128") == false);
    CHECK(match_cidr("2001:db8::1", "::/0") == true);
    CHECK(match_cidr("2001:db8::1", "2001:db8::1") == true); /* implicit /128 */
    CHECK(match_cidr("2001:db8::1", "2001:db8::/121") == true);
    CHECK(match_cidr("2001:db8::80", "2001:db8::/121") == false);
    CHECK(match_cidr("2001:db8::80", "2001:db8::80/121") == true);
    CHECK(match_cidr("2001:db8::81", "2001:db8::80/121") == true);

    /* 5. IPv6 invalid prefixes */
    CHECK(match_cidr("2001:db8::1", "2001:db8::/129") == false);
    CHECK(match_cidr("2001:db8::1", "2001:db8::/-5") == false);
    CHECK(match_cidr("2001:db8::1", "2001:db8::/xyz") == false);

    /* 6. Address family mismatches */
    CHECK(match_cidr("192.0.2.1", "2001:db8::/32") == false);
    CHECK(match_cidr("2001:db8::1", "192.0.2.0/24") == false);
    CHECK(match_cidr("invalid_ip", "192.0.2.0/24") == false);

    printf("  -> match_cidr helper coverage verified.\n");
}

/* ------------------------------------------------------------------------ */
static void test_config_negative_patterns(void) {
    printf("[TEST] config parser: comprehensive error & warning branch coverage...\n");

    /* 1. Unmatched braces and unexpected tokens */
    expect_reject("unmatched open brace at EOF", "options { port 53; ");
    expect_reject("unmatched closing brace (extra token)", "options { port 53; }; };");
    expect_reject("zone with unmatched brace", "zone \"example.com\" { type master; file \"z\"; ");
    expect_reject("options with unexpected nested brace", "options { { }; };");

    /* 2. Missing required parameters and semicolons */
    expect_reject("options missing value for port", "options { port; };");
    expect_reject("options missing semicolon after port", "options { port 53 };");
    expect_reject("view missing name", "view { zone \"a.com\" { type master; file \"z\"; }; };");

    /* 3. Zone type, file-format, and auto-tc-flag errors */
    expect_reject("unknown zone type", "zone \"example.com\" { type bogus_type; file \"z\"; };");
    expect_reject("invalid file-format", "zone \"example.com\" { type master; file \"z\"; file-format yaml; };");
    expect_reject("invalid disable-auto-tc-flag", "zone \"example.com\" { type master; file \"z\"; disable-auto-tc-flag bogus; };");

    /* 4. Cookie secrets & algorithm validation */
    expect_reject("cookie-secret not 32 hex digits (short)", "options { cookie-secret \"0123456789abcdef\"; };");
    expect_reject("cookie-secret not hex digits (invalid chars)", "options { cookie-secret \"0123456789abcdef0123456789abcdeg\"; };");
    expect_reject("too many cookie secrets (> 4)",
                  "options { "
                  "cookie-secret \"0123456789abcdef0123456789abcdef\"; "
                  "cookie-secret \"0123456789abcdef0123456789abcde0\"; "
                  "cookie-secret \"0123456789abcdef0123456789abcde1\"; "
                  "cookie-secret \"0123456789abcdef0123456789abcde2\"; "
                  "cookie-secret \"0123456789abcdef0123456789abcde3\"; };");
    expect_reject("unsupported cookie algorithm", "options { cookie-algorithm sha256; };");

    /* 5. Query log & cache buffer size validation */
    expect_reject("query-log-buffer-size non power-of-2", "options { query-log-buffer-size 3000; };");
    expect_reject("query-log-buffer-size too small (< 1024)", "options { query-log-buffer-size 512; };");
    expect_reject("query-log-buffer-size too large (> 1048576)", "options { query-log-buffer-size 2097152; };");
    expect_reject("query-log-buffer-size invalid string", "options { query-log-buffer-size abc; };");
    expect_reject("query-log-max-qps invalid string", "options { query-log-max-qps abc; };");
    expect_reject("wire-cache-max-records invalid string", "options { wire-cache-max-records non_numeric; };");

    /* 6. Unsupported TSIG algorithms and invalid secrets */
    expect_reject("key with unsupported TSIG algorithm",
                  "key \"k1\" { algorithm bogus-algo; secret \"c2VjcmV0MTIz\"; };");
    expect_reject("control-channel with unsupported algorithm",
                  "control-channel { algorithm invalid-algo; secret \"c2VjcmV0MTIz\"; };");
    expect_reject("key with empty secret",
                  "key \"k1\" { algorithm hmac-sha256; secret \"\"; };");

    /* 7. Undefined TSIG keys in zone references */
    expect_reject("zone references undefined tsig-key",
                  "zone \"example.com\" { type master; file \"z\"; tsig-key \"non_existent_key\"; };");
    expect_reject("zone allow-transfer references undefined tsig-key",
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { key non_existent_key; }; };");

    /* 8. Duplicate definitions */
    expect_reject("duplicate zone in flat config",
                  "zone \"example.com\" { type master; file \"z1\"; }; "
                  "zone \"example.com\" { type master; file \"z2\"; };");
    expect_reject("duplicate zone in same view",
                  "view \"v1\" { "
                  "zone \"example.com\" { type master; file \"z1\"; }; "
                  "zone \"example.com\" { type master; file \"z2\"; }; };");
    expect_reject("duplicate view name",
                  "view \"v1\" { zone \"a.com\" { type master; file \"z1\"; }; }; "
                  "view \"v1\" { zone \"b.com\" { type master; file \"z2\"; }; };");
    expect_reject("duplicate key name",
                  "key \"k1\" { algorithm hmac-sha256; secret \"" SECRET_OK "\"; }; "
                  "key \"k1\" { algorithm hmac-sha256; secret \"" SECRET_OK "\"; };");

    /* 9. Undefined logging channel reference */
    expect_reject("logging queries references undefined channel",
                  "logging { category queries { non_existent_channel; }; };");
    expect_reject("logging responses references undefined channel",
                  "logging { category responses { non_existent_channel; }; };");

    /* 10. Mixing flat zones and views */
    expect_reject("mixing flat zone and view blocks",
                  "zone \"flat.com\" { type master; file \"z\"; }; "
                  "view \"v1\" { zone \"v.com\" { type master; file \"z\"; }; };");

    /* 11. Valid warning path configurations (should parse successfully and hit warning branches) */
    server_config_t cfg;
    /* Deprecated MD5/SHA1 TSIG keys */
    if (parse_ok("key \"k_md5\" { algorithm hmac-md5; secret \"c2VjcmV0MTIz\"; }; "
                 "control-channel { algorithm hmac-sha1; secret \"c2VjcmV0MTIz\"; };", &cfg)) {
        free_server_config_fields(&cfg);
    }
    /* Program & forward zone with superfluous file and masters */
    if (parse_ok("zone \"p.com\" { type program; program \"/bin/echo\"; file \"z\"; masters { 1.2.3.4; }; }; "
                 "zone \"f.com\" { type forward; forwarders { 1.2.3.4; }; file \"z\"; masters { 1.2.3.4; }; };", &cfg)) {
        free_server_config_fields(&cfg);
    }

    printf("  -> config parser error & warning branches verified.\n");
}

/* notify-retries / notify-retry-interval / notify-retry-backoff (RFC 1996 §3.6: operator parameters,
 * defaults 60 s and 5 retransmissions). docs/karidns.md: options and zone, zone overrides options. */
static void test_notify_retry(void) {
    printf("[TEST] notify-retries / notify-retry-interval / notify-retry-backoff...\n");
    server_config_t cfg;
    if (parse_ok("options { };", &cfg)) {
        notify_retry_config_t r = notify_retry_effective(&cfg, NULL);
        CHECK(r.retries == 5 && r.interval == 60 && r.backoff == NOTIFY_BACKOFF_FIXED);
        free_server_config_fields(&cfg);
    }
    /* no configuration at all: the built-in defaults */
    notify_retry_config_t d = notify_retry_effective(NULL, NULL);
    CHECK(d.retries == 5 && d.interval == 60 && d.backoff == NOTIFY_BACKOFF_FIXED);

    if (parse_ok("options { notify-retries 3; notify-retry-interval 3; notify-retry-backoff exponential; };"
                 "zone \"a.example\" { type master; file \"a.zone\"; notify-retry-interval 10; };"
                 "zone \"b.example\" { type master; file \"b.zone\"; notify-retries 0; notify-retry-backoff FIXED; };"
                 "zone \"c.example\" { type master; file \"c.zone\"; };", &cfg)) {
        const zone_config_t *a = first_zone(&cfg);
        const zone_config_t *b = a ? a->next : NULL;
        const zone_config_t *c = b ? b->next : NULL;
        CHECK(cfg.notify_retry.retries == 3 && cfg.notify_retry.interval == 3);
        CHECK(cfg.notify_retry.backoff == NOTIFY_BACKOFF_EXPONENTIAL);
        notify_retry_config_t ra = notify_retry_effective(&cfg, a);
        CHECK(ra.retries == 3 && ra.interval == 10 && ra.backoff == NOTIFY_BACKOFF_EXPONENTIAL);
        notify_retry_config_t rb = notify_retry_effective(&cfg, b);
        CHECK(rb.retries == 0 && rb.interval == 3 && rb.backoff == NOTIFY_BACKOFF_FIXED);
        notify_retry_config_t rc = notify_retry_effective(&cfg, c);
        CHECK(rc.retries == 3 && rc.interval == 3 && rc.backoff == NOTIFY_BACKOFF_EXPONENTIAL);
        CHECK(c && !zext(c)->notify_retry.retries_set && !zext(c)->notify_retry.interval_set && !zext(c)->notify_retry.backoff_set);
        free_server_config_fields(&cfg);
    }
    /* range boundaries are inclusive */
    if (parse_ok("options { notify-retries 10; notify-retry-interval 3600; };", &cfg)) {
        CHECK(cfg.notify_retry.retries == 10 && cfg.notify_retry.interval == 3600);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { notify-retries 0; notify-retry-interval 1; };", &cfg)) {
        CHECK(cfg.notify_retry.retries == 0 && cfg.notify_retry.interval == 1);
        free_server_config_fields(&cfg);
    }
    expect_reject("notify-retries above 10", "options { notify-retries 11; };");
    expect_reject("notify-retries negative", "options { notify-retries -1; };");
    expect_reject("notify-retry-interval 0", "options { notify-retry-interval 0; };");
    expect_reject("notify-retry-interval above 3600", "options { notify-retry-interval 3601; };");
    expect_reject("notify-retry-interval junk", "options { notify-retry-interval 60s; };");
    expect_reject("notify-retry-backoff unknown", "options { notify-retry-backoff linear; };");
    expect_reject("notify-retry-backoff missing semicolon", "options { notify-retry-backoff fixed };");
    expect_reject("zone notify-retries out of range",
                  "zone \"a.example\" { type master; file \"a.zone\"; notify-retries 99; };");
    expect_reject("zone notify-retry-backoff unknown",
                  "zone \"a.example\" { type master; file \"a.zone\"; notify-retry-backoff 2; };");
}

/* ixfr-history <n>: how many past versions are kept as IXFR diffs (RFC 1995 §4), 0..32, default 4; options and
 * zone, a zone overrides options (S5 B-3). */
static void test_ixfr_history_option(void) {
    printf("[TEST] ixfr-history option (options and zone, range 0..32, default 4)...\n");
    server_config_t cfg;
    if (parse_ok("options { };", &cfg)) {
        CHECK(cfg.ixfr_history == IXFR_HISTORY_DEFAULT && IXFR_HISTORY_DEFAULT == 4);
        CHECK(ixfr_history_effective(&cfg, NULL) == 4);
        free_server_config_fields(&cfg);
    }
    CHECK(ixfr_history_effective(NULL, NULL) == 4);   /* no configuration at all: the built-in default */

    if (parse_ok("options { ixfr-history 2; };"
                 "zone \"a.example\" { type master; file \"a.zone\"; ixfr-history 0; };"
                 "zone \"b.example\" { type master; file \"b.zone\"; ixfr-history 32; };"
                 "zone \"c.example\" { type master; file \"c.zone\"; };", &cfg)) {
        const zone_config_t *a = first_zone(&cfg);
        const zone_config_t *b = a ? a->next : NULL;
        const zone_config_t *c = b ? b->next : NULL;
        CHECK(cfg.ixfr_history == 2);
        CHECK(a && zext(a)->ixfr_history_set && zext(a)->ixfr_history == 0 && ixfr_history_effective(&cfg, a) == 0);
        CHECK(b && zext(b)->ixfr_history_set && zext(b)->ixfr_history == 32 && ixfr_history_effective(&cfg, b) == 32);
        CHECK(c && !zext(c)->ixfr_history_set && ixfr_history_effective(&cfg, c) == 2);   /* the zone inherits options */
        free_server_config_fields(&cfg);
    }
    /* a zone without the option, no options value: the default */
    if (parse_ok("zone \"a.example\" { type master; file \"a.zone\"; };", &cfg)) {
        CHECK(ixfr_history_effective(&cfg, first_zone(&cfg)) == IXFR_HISTORY_DEFAULT);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { ixfr-history 0; };", &cfg)) {
        CHECK(cfg.ixfr_history == 0);
        free_server_config_fields(&cfg);
    }
    expect_reject("ixfr-history above 32", "options { ixfr-history 33; };");
    expect_reject("ixfr-history negative", "options { ixfr-history -1; };");
    expect_reject("ixfr-history junk", "options { ixfr-history 4x; };");
    expect_reject("ixfr-history word", "options { ixfr-history many; };");
    expect_reject("ixfr-history missing value", "options { ixfr-history; };");
    expect_reject("ixfr-history missing semicolon", "options { ixfr-history 4 };");
    expect_reject("zone ixfr-history above 32",
                  "zone \"a.example\" { type master; file \"a.zone\"; ixfr-history 99; };");
    expect_reject("zone ixfr-history negative",
                  "zone \"a.example\" { type master; file \"a.zone\"; ixfr-history -2; };");
    expect_reject("zone ixfr-history empty",
                  "zone \"a.example\" { type master; file \"a.zone\"; ixfr-history ; };");
}

/* ------------------------------------------------------------------------ */
/* Phase 12: D-02 (the other boolean statements), D-01 (category lists), D-23 (type case), D-22 (acl) */
static void test_boolean_statements_everywhere(void) {
    printf("[TEST] D-02: one boolean rule in zone, rate-limit, dnstap and logging statements...\n");
    server_config_t cfg;
    if (parse_ok("zone \"cat.test\" { type master; file \"c\"; catalog-zone TRUE; disable-auto-tc-flag 1; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->is_catalog == true && zext(z)->disable_auto_tc_flag == true);
        free_server_config_fields(&cfg);
    }
    expect_reject("catalog-zone maybe", "zone \"cat.test\" { type master; file \"c\"; catalog-zone maybe; };");
    expect_reject("disable-auto-tc-flag maybe", "zone \"cat.test\" { type master; file \"c\"; disable-auto-tc-flag maybe; };");
    if (parse_ok("options { rate-limit { responses-per-second 5; log-only Yes; early-drop 0; }; };", &cfg)) {
        CHECK(cfg.rrl.log_only == true && cfg.rrl.early_drop == false);
        free_server_config_fields(&cfg);
    }
    expect_reject("rate-limit log-only maybe", "options { rate-limit { log-only maybe; }; };");
    expect_reject("rate-limit early-drop maybe", "options { rate-limit { early-drop maybe; }; };");
    if (parse_ok("dnstap { socket \"/tmp/x.sock\"; log-queries TRUE; log-responses No; require-connect 1; };", &cfg)) {
        CHECK(cfg.dnstap.log_auth_query == true && cfg.dnstap.log_auth_response == false);
        CHECK(cfg.dnstap.require_connect == true);
        free_server_config_fields(&cfg);
    }
    expect_reject("dnstap log-queries maybe", "dnstap { socket \"/tmp/x.sock\"; log-queries maybe; };");
    expect_reject("dnstap require-connect maybe", "dnstap { socket \"/tmp/x.sock\"; require-connect maybe; };");
    /* print-time true used to be read as "no" (only the word yes was accepted) */
    if (parse_ok("logging { channel q { file \"/tmp/q.log\"; print-time true; print-category 1; print-severity YES; }; };", &cfg)) {
        const log_channel_t *c = cfg.logging.channels;
        CHECK(c && c->print_time == true && c->print_category == true && c->print_severity == true);
        free_server_config_fields(&cfg);
    }
    expect_reject("print-time maybe", "logging { channel q { file \"/tmp/q.log\"; print-time maybe; }; };");
}

static void test_logging_category_lists(void) {
    printf("[TEST] D-01: category with several channels uses the first one...\n");
    server_config_t cfg;
    if (parse_ok("logging { channel a { file \"/tmp/a.log\"; }; channel b { file \"/tmp/b.log\"; };"
                 "  category queries { a; b; }; category responses { b; a; }; };", &cfg)) {
        CHECK_STR(cfg.logging.queries_channel_name, "a");
        CHECK(cfg.logging.queries_channel && strcmp(cfg.logging.queries_channel->name, "a") == 0);
        CHECK_STR(cfg.logging.responses_channel_name, "b");
        free_server_config_fields(&cfg);
    }
    /* an empty list turns the category off; a later definition replaces an earlier one */
    if (parse_ok("logging { channel a { file \"/tmp/a.log\"; }; category queries { a; }; category queries { }; };", &cfg)) {
        CHECK(cfg.logging.queries_channel_name == NULL && cfg.logging.queries_channel == NULL);
        free_server_config_fields(&cfg);
    }
    /* only the first channel is used; the others are ignored (with a warning), even undefined ones */
    if (parse_ok("logging { channel a { file \"/tmp/a.log\"; }; category queries { a; undefined_b; }; };", &cfg)) {
        CHECK_STR(cfg.logging.queries_channel_name, "a");
        free_server_config_fields(&cfg);
    }
    expect_reject("category list without ';'", "logging { channel a { file \"/tmp/a.log\"; }; category queries { a b; }; };");
    expect_reject("category without braces", "logging { channel a { file \"/tmp/a.log\"; }; category queries a; };");
    expect_reject("unterminated channel (no leak of the channel)", "logging { channel a { file \"/tmp/a.log\"; print-time maybe; ");
}

static void test_zone_type_case(void) {
    printf("[TEST] D-23: zone type names are stored in lower case...\n");
    static const struct { const char *word; const char *stored; } t[] = {
        { "Master", "master" }, { "PRIMARY", "master" }, { "Slave", "slave" }, { "Secondary", "slave" },
        { "FORWARD", "forward" },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        char txt[256];
        server_config_t cfg;
        snprintf(txt, sizeof(txt), "zone \"example.com\" { type %s; file \"z\"; masters { 192.0.2.1; }; "
                 "forwarders { 192.0.2.1; }; };", t[i].word);
        if (parse_ok(txt, &cfg)) {
            const zone_config_t *z = first_zone(&cfg);
            CHECK(z != NULL);
            if (z) CHECK_STR(z->type, t[i].stored);
            free_server_config_fields(&cfg);
        }
    }
    server_config_t cfg;
    /* a second type statement replaces the first (no leak under ASan) */
    if (parse_ok("zone \"example.com\" { type master; type Secondary; file \"z\"; masters { 192.0.2.1; }; };", &cfg)) {
        CHECK_STR(first_zone(&cfg)->type, "slave");
        free_server_config_fields(&cfg);
    }
}

static bool acl_has(char **list, int count, const char *entry) {
    for (int i = 0; i < count; i++)
        if (list[i] && strcmp(list[i], entry) == 0) return true;
    return false;
}

static void test_named_acls(void) {
    printf("[TEST] D-22: acl statements, references and invalid entries...\n");
    server_config_t cfg;
    /* used before it is defined, nested, negated, with a key */
    if (parse_ok("key \"k1\" { algorithm hmac-sha256; secret \"" SECRET_OK "\"; };"
                 "zone \"example.com\" { type master; file \"z\";"
                 "  allow-transfer { xfr; }; allow-update { !blocked; upd; }; };"
                 "acl \"inner\" { 192.0.2.0/24; };"
                 "acl xfr { inner; 2001:db8::/32; key k1; };"
                 "acl blocked { 192.0.2.66; };"
                 "acl \"upd\" { 198.51.100.7; key \"k1\"; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z != NULL);
        if (z) {
            CHECK(zext(z)->allow_transfer_count == 2);
            CHECK(acl_has(zext(z)->allow_transfer, zext(z)->allow_transfer_count, "192.0.2.0/24"));
            CHECK(acl_has(zext(z)->allow_transfer, zext(z)->allow_transfer_count, "2001:db8::/32"));
            CHECK(zext(z)->tsig_keys_count == 1 && zext(z)->tsig_keys && strcmp(zext(z)->tsig_keys[0], "k1") == 0);
            /* allow-update: !192.0.2.66 first, then the address and the key name */
            CHECK(zext(z)->allow_update_count == 3);
            CHECK(zext(z)->allow_update_count == 3 && strcmp(zext(z)->allow_update[0], "!192.0.2.66") == 0);
            CHECK(acl_has(zext(z)->allow_update, zext(z)->allow_update_count, "198.51.100.7"));
            CHECK(acl_has(zext(z)->allow_update, zext(z)->allow_update_count, "k1"));
            CHECK(check_acl_bin("192.0.2.5", zext(z)->allow_transfer_parsed, zext(z)->allow_transfer_count));
            CHECK(!check_acl_bin("203.0.113.5", zext(z)->allow_transfer_parsed, zext(z)->allow_transfer_count));
            CHECK(!check_acl_bin("192.0.2.66", zext(z)->allow_update_parsed, zext(z)->allow_update_count));
            CHECK(check_acl_bin("198.51.100.7", zext(z)->allow_update_parsed, zext(z)->allow_update_count));
        }
        free_server_config_fields(&cfg);
    }
    /* !name negates each entry, as "! { ... };" does; match-clients and ecs-trusted-resolvers expand too */
    if (parse_ok("acl lan { 192.0.2.0/24; !192.0.2.9; };"
                 "options { ecs-trusted-resolvers { lan; }; };"
                 "view \"v\" { match-clients { !lan; any; }; zone \"example.com\" { type master; file \"z\"; }; };", &cfg)) {
        const view_config_t *v = cfg.views;
        CHECK(v && v->match_clients_count == 3);
        if (v && v->match_clients_count == 3) {
            CHECK_STR(v->match_clients[0], "!192.0.2.0/24");
            CHECK_STR(v->match_clients[1], "192.0.2.9");
            CHECK_STR(v->match_clients[2], "any");
            CHECK(!check_acl_bin("192.0.2.1", v->match_clients_parsed, v->match_clients_count));
            CHECK(check_acl_bin("203.0.113.1", v->match_clients_parsed, v->match_clients_count));
        }
        CHECK(cfg.ecs_trusted_resolvers_count == 2);
        free_server_config_fields(&cfg);
    }
    /* none is accepted and never matches; a bare defined key name stays valid in allow-update */
    if (parse_ok("key \"k1\" { algorithm hmac-sha256; secret \"" SECRET_OK "\"; };"
                 "zone \"example.com\" { type master; file \"z\"; allow-transfer { none; }; allow-update { k1; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->allow_transfer_count == 1 && !check_acl_bin("192.0.2.1", zext(z)->allow_transfer_parsed, 1));
        CHECK(z && zext(z)->allow_update_count == 1 && strcmp(zext(z)->allow_update[0], "k1") == 0);
        free_server_config_fields(&cfg);
    }
    /* invalid entries are configuration errors (they used to never match, silently) */
    expect_reject("allow-transfer with a bad address",
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { 192.0.2.300; }; };");
    expect_reject("allow-transfer with a bad prefix",
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { 192.0.2.0/33; }; };");
    expect_reject("allow-transfer with an undefined acl name",
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { secondaries; }; };");
    expect_reject("allow-update with an undefined name (neither acl nor key)",
                  "zone \"example.com\" { type master; file \"z\"; allow-update { typo_key; }; };");
    expect_reject("match-clients with an undefined acl",
                  "view \"v\" { match-clients { nowhere; }; zone \"example.com\" { type master; file \"z\"; }; };");
    expect_reject("ecs-trusted-resolvers with a bad entry", "options { ecs-trusted-resolvers { resolver1; }; };");
    expect_reject("localhost is not supported",
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { localhost; }; };");
    expect_reject("localnets is not supported",
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { localnets; }; };");
    expect_reject("acl with a bad entry",
                  "acl bad { 999.1.1.1; }; zone \"example.com\" { type master; file \"z\"; allow-transfer { bad; }; };");
    expect_reject("duplicate acl (case-insensitive)", "acl a { any; }; acl A { none; };");
    expect_reject("acl named like a built-in", "acl any { 192.0.2.1; };");
    expect_reject("acl loop", "acl a { b; }; acl b { a; };"
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { a; }; };");
    expect_reject("acl with a key used in match-clients",
                  "key \"k1\" { algorithm hmac-sha256; secret \"" SECRET_OK "\"; }; acl k { key k1; };"
                  "view \"v\" { match-clients { k; }; zone \"example.com\" { type master; file \"z\"; }; };");
    expect_reject("acl with an undefined key",
                  "acl k { key nokey; }; zone \"example.com\" { type master; file \"z\"; allow-transfer { k; }; };");
    expect_reject("negated key through an acl",
                  "key \"k1\" { algorithm hmac-sha256; secret \"" SECRET_OK "\"; }; acl k { key k1; };"
                  "zone \"example.com\" { type master; file \"z\"; allow-transfer { !k; }; };");
    expect_reject("acl without a body", "acl a;");
}

/* ------------------------------------------------------------------------ */
/* Zone config index (view_find_zone_config): same names as domain_names_match_ci(), built while
 * parsing, also used for the duplicate check. */
static void test_zone_config_index(void) {
    printf("[TEST] zone config index...\n");
    server_config_t cfg;
    if (parse_ok("view \"a\" { match-clients { 192.0.2.0/24; };"
                 "  zone \"one.test\" { type master; file \"a1\"; };"
                 "  zone \"Sub.Example.TEST.\" { type master; file \"a2\"; }; };"
                 "view \"b\" { match-clients { any; };"
                 "  zone \"one.test\" { type master; file \"b1\"; }; };", &cfg)) {
        const view_config_t *va = cfg.views, *vb = va ? va->next : NULL;
        CHECK(va && vb && va->zone_index.slots && vb->zone_index.slots);
        if (va && vb) {
            const zone_config_t *z = view_find_zone_config(va, "ONE.test.");
            CHECK(z && strcmp(z->file, "a1") == 0);
            z = view_find_zone_config(vb, "one.test");
            CHECK(z && strcmp(z->file, "b1") == 0);
            z = view_find_zone_config(va, "sub.example.test");
            CHECK(z && strcmp(z->file, "a2") == 0);
            CHECK(view_find_zone_config(va, "example.test") == NULL);
            CHECK(view_find_zone_config(va, "one.test..") == NULL);
            CHECK(view_find_zone_config(vb, "sub.example.test.") == NULL);
        }
        free_server_config_fields(&cfg);
    }

    /* top-level zones: the index moves to the default view */
    if (parse_ok("zone \"x.test\" { type master; file \"x\"; }; zone \"y.test\" { type master; file \"y\"; };", &cfg)) {
        CHECK(cfg.views && cfg.views->zone_index.slots && cfg.views->zone_index.count == 2);
        CHECK(cfg.top_zone_index.slots == NULL);
        const zone_config_t *z = cfg.views ? view_find_zone_config(cfg.views, "Y.TEST.") : NULL;
        CHECK(z && strcmp(z->file, "y") == 0);
        free_server_config_fields(&cfg);
    }

    /* duplicates use the lookup rule: trailing dot and case do not make a different zone */
    expect_reject("dup in view (trailing dot)",
                  "view \"a\" { zone \"dup.test\" { type master; file \"1\"; };"
                  " zone \"dup.test.\" { type master; file \"2\"; }; };");
    expect_reject("dup top-level (case)",
                  "zone \"dup.test\" { type master; file \"1\"; }; zone \"DUP.test\" { type master; file \"2\"; };");

    /* many zones: growth and probing */
    enum { N = 3000 };
    size_t cap = (size_t)N * 64 + 64;
    char *txt = malloc(cap);
    if (txt) {
        size_t off = 0;
        for (int i = 0; i < N; i++)
            off += (size_t)snprintf(txt + off, cap - off, "zone \"z%05d.test\" { type master; file \"f\"; };", i);
        if (parse_ok(txt, &cfg)) {
            CHECK(cfg.views && cfg.views->zone_index.count == N);
            int found = 0;
            char name[32];
            for (int i = 0; i < N; i++) {
                snprintf(name, sizeof(name), "Z%05d.TEST.", i);
                if (cfg.views && view_find_zone_config(cfg.views, name)) found++;
            }
            CHECK(found == N);
            CHECK(view_find_zone_config(cfg.views, "z99999.test") == NULL);
            free_server_config_fields(&cfg);
        }
        free(txt);
    }

    /* a view built by hand (no index) falls back to the linear search */
    zone_config_t hz = {0};
    hz.domain = "hand.test";
    view_config_t hv = {0};
    hv.zones = &hz;
    CHECK(view_find_zone_config(&hv, "HAND.test.") == &hz);
    CHECK(view_find_zone_config(&hv, "other.test") == NULL);
}

/* S6a: zone_config_t keeps only domain/file/type/is_catalog/ext/next; the rarely set options live in zone_ext_t, which
 * a zone gets only when it sets at least one of them (ext == NULL means every option is at its default). */
static void test_zone_ext_layout(void) {
    printf("[TEST] zone_config_t core / zone_ext_t override block (S6a)...\n");
    CHECK(sizeof(zone_config_t) <= 48);
    server_config_t cfg;
    if (parse_ok("options { notify-retries 3; notify-retry-interval 7; ixfr-history 9; additional-from-auth in-domain; };"
                 "zone \"plain.example\" { type master; file \"plain.zone\"; };"
                 "zone \"empty-type.example\" { file \"x.zone\"; };"
                 "zone \"one.example\" { type master; file \"one.zone\"; notify-retries 1; };"
                 "zone \"acl.example\" { type master; file \"acl.zone\"; allow-transfer { 192.0.2.1; }; };"
                 "zone \"cat.example\" { type master; file \"cat.zone\"; catalog-zone yes; };", &cfg)) {
        const zone_config_t *plain = first_zone(&cfg);
        const zone_config_t *def = plain ? plain->next : NULL;
        const zone_config_t *one = def ? def->next : NULL;
        const zone_config_t *acl = one ? one->next : NULL;
        const zone_config_t *cat = acl ? acl->next : NULL;
        CHECK(plain && def && one && acl && cat && cat->next == NULL);
        /* nothing set: no override block, every accessor value is the default */
        CHECK(plain && plain->ext == NULL && zext(plain) == &zone_ext_default);
        CHECK(def && def->ext == NULL && def->type && strcmp(def->type, "master") == 0);
        CHECK(plain && zext(plain)->masters_count == 0 && zext(plain)->allow_transfer == NULL &&
              !zext(plain)->additional_from_auth_specified && zext(plain)->zone_udp_bufsize == 0);
        /* catalog-zone is a core flag, not an option */
        CHECK(cat && cat->is_catalog && cat->ext == NULL);
        /* one option set: a block, and the other options still come from options{} */
        CHECK(one && one->ext != NULL && zext(one)->notify_retry.retries_set && zext(one)->notify_retry.retries == 1);
        notify_retry_config_t r = notify_retry_effective(&cfg, one);
        CHECK(r.retries == 1 && r.interval == 7 && r.backoff == NOTIFY_BACKOFF_FIXED);
        CHECK(!zext(one)->notify_retry.interval_set && !zext(one)->ixfr_history_set);
        CHECK(ixfr_history_effective(&cfg, one) == 9);
        CHECK(ixfr_history_effective(&cfg, plain) == 9);
        CHECK(acl && acl->ext != NULL && zext(acl)->allow_transfer_count == 1 && zext(acl)->allow_transfer_parsed != NULL);
        CHECK(cfg.additional_from_auth == ADDITIONAL_AUTH_IN_DOMAIN && !zext(acl)->additional_from_auth_specified);
        free_server_config_fields(&cfg);
    }
    /* an option block holding only zero values is dropped too; explicit zeros that carry meaning are kept */
    if (parse_ok("zone \"z.example\" { type master; file \"z.zone\"; notify-retries 0; ixfr-history 0; };"
                 "zone \"y.example\" { type master; file \"y.zone\"; masters { }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->ext && zext(z)->notify_retry.retries_set && zext(z)->notify_retry.retries == 0);
        CHECK(z && zext(z)->ixfr_history_set && zext(z)->ixfr_history == 0);
        free_server_config_fields(&cfg);
    }
}

/* S6a: no complete copy of the zone list is made: the parsed configuration has no top-level list, every view's
 * list is the one list, and the "all zones" helpers see the zones in view order. */
static void test_zone_flat_list_removed(void) {
    printf("[TEST] no flat zone copy; config_find_zone_any_view / CONFIG_FOR_EACH_ZONE order (S6a)...\n");
    server_config_t cfg;
    if (parse_ok("view \"v1\" { match-clients { 192.0.2.0/24; };"
                 "  zone \"a.example\" { type master; file \"a.zone\"; masters { 192.0.2.9; }; };"
                 "  zone \"b.example\" { type master; file \"b.zone\"; }; };"
                 "view \"v2\" { match-clients { any; };"
                 "  zone \"c.example\" { type master; file \"c.zone\"; };"
                 "  zone \"a.example\" { type master; file \"a2.zone\"; }; };", &cfg)) {
        CHECK(cfg.zones == NULL);
        const char *want[] = {"a.example.", "b.example.", "c.example.", "a.example."};
        const char *want_file[] = {"a.zone", "b.zone", "c.zone", "a2.zone"};
        int n = 0;
        const view_config_t *v;
        zone_config_t *z;
        CONFIG_FOR_EACH_ZONE(&cfg, v, z) {
            CHECK(n < 4 && strcmp(z->domain, want[n]) == 0 && strcmp(z->file, want_file[n]) == 0);
            /* the very zone object of the view (no copy): the view's index finds this same pointer */
            CHECK(view_find_zone_config(v, z->domain) == z);
            n++;
        }
        CHECK(n == 4);
        /* first match in view order; the options of the view-1 zone are the ones the shared object carries */
        zone_config_t *any = config_find_zone_any_view(&cfg, "A.EXAMPLE");
        CHECK(any && strcmp(any->file, "a.zone") == 0 && zext(any)->masters_count == 1);
        CHECK(any == view_find_zone_config(cfg.views, "a.example"));
        CHECK(config_find_zone_any_view(&cfg, "c.example") == cfg.views->next->zones);
        CHECK(config_find_zone_any_view(&cfg, "nope.example") == NULL);
        free_server_config_fields(&cfg);
    }
    /* top-level zones move into the default view; the config keeps no list of its own */
    if (parse_ok(ZONE_MIN, &cfg)) {
        CHECK(cfg.zones == NULL && cfg.views && cfg.views->zones && config_find_zone_any_view(&cfg, "example.com") == cfg.views->zones);
        free_server_config_fields(&cfg);
    }
}

/* ------------------------------------------------------------------------ */
/* B7a (beta design D14, 1.3, 3.5): transfer-acl-match / update-acl-match, the restricted parse of the settings text of DB
 * zones, and the ACL evaluation with acl-ceiling (dns_tsig_acl.c).  The expectations follow the definitions in
 * docs/karidns.md: file zones keep "address AND key" for transfers and "address OR key" for updates unless the option says
 * otherwise; a DB ACL needs the ceiling too. */
static zone_ext_shared_t *db_parse_quiet(const char *text, char *err, size_t errlen) {
    fflush(stderr);
    int saved = dup(2);
    int nul = open("/dev/null", O_WRONLY);
    if (nul >= 0) { dup2(nul, 2); close(nul); }
    zone_ext_shared_t *sh = db_settings_parse(text, strlen(text), err, errlen);
    fflush(stderr);
    if (saved >= 0) { dup2(saved, 2); close(saved); }
    return sh;
}

static void expect_db_reject(const char *text, const char *want_in_error) {
    char err[200];
    zone_ext_shared_t *sh = db_parse_quiet(text, err, sizeof(err));
    g_checks++;
    if (sh) {
        g_failed++;
        printf("  [FAIL] settings text should be refused: %s\n", text);
        zone_ext_shared_unref(sh);
        return;
    }
    g_checks++;
    if (!err[0] || (want_in_error && !strstr(err, want_in_error))) {
        g_failed++;
        printf("  [FAIL] refusal of '%s' says '%s', want it to contain '%s'\n", text, err, want_in_error ? want_in_error : "(anything)");
    }
}

static zone_config_t *db_zone_from(const char *text) {
    char err[200];
    zone_ext_shared_t *sh = db_parse_quiet(text, err, sizeof(err));
    CHECK(sh != NULL);
    if (!sh) return NULL;
    zone_config_t *z = calloc(1, sizeof(*z));
    z->domain = strdup("db.test.");
    z->type = strdup("master");
    z->ext = &sh->ext;                      /* takes the reference db_settings_parse() returned */
    z->ext_shared = true;
    return z;
}

/* B8: ecs-trusted-resolvers in the settings text of a DB zone */
static void test_db_ecs_trusted(void) {
    char err[200];
    zone_ext_shared_t *sh = db_parse_quiet("ecs-trusted-resolvers { 127.0.0.2; !192.0.2.0/25; 192.0.2.0/24; 2001:db8::/32; };", err, sizeof(err));
    CHECK(sh != NULL);
    if (sh) {
        CHECK(sh->ext.ecs_trusted_resolvers_count == 4 && sh->ext.ecs_trusted_resolvers_parsed && sh->ext.db_acl_ceiling);
        CHECK(sh->ext.ecs_trusted_resolvers_parsed[1].is_deny);
        zone_ext_shared_unref(sh);
    }
    /* a later statement replaces the earlier one (profile text first, zone text after it) */
    sh = db_parse_quiet("ecs-trusted-resolvers { 192.0.2.1; 192.0.2.2; }; ecs-trusted-resolvers { 198.51.100.1; };", err, sizeof(err));
    CHECK(sh != NULL && sh->ext.ecs_trusted_resolvers_count == 1 && strcmp(sh->ext.ecs_trusted_resolvers[0], "198.51.100.1") == 0);
    if (sh) zone_ext_shared_unref(sh);
    expect_db_reject("ecs-trusted-resolvers { resolver.example; };", "ecs-trusted-resolvers");
    expect_db_reject("ecs-trusted-resolvers { 192.0.2.1 };", NULL);
    expect_db_reject("ecs-tags { };", "not allowed");
}

static void test_db_settings_and_acl_match(void) {
    printf("[TEST] transfer-acl-match / update-acl-match, DB zone settings (restricted parse), acl-ceiling...\n");
    server_config_t cfg;
    char txt[2048];

    /* the options exist in karidns.conf zones; defaults are 0 (the old meaning), other words are errors */
    if (parse_ok("zone \"a.test\" { type master; file \"a\"; transfer-acl-match any; update-acl-match all; };"
                 "zone \"b.test\" { type master; file \"b\"; transfer-acl-match ALL; update-acl-match Any; };"
                 "zone \"c.test\" { type master; file \"c\"; allow-transfer { 192.0.2.1; }; };", &cfg)) {
        const zone_config_t *a = first_zone(&cfg), *b = a ? a->next : NULL, *c = b ? b->next : NULL;
        CHECK(a && zext(a)->transfer_acl_match == ACL_MATCH_ANY && zext(a)->update_acl_match == ACL_MATCH_ALL);
        CHECK(b && zext(b)->transfer_acl_match == ACL_MATCH_ALL && zext(b)->update_acl_match == ACL_MATCH_ANY);
        CHECK(c && zext(c)->transfer_acl_match == ACL_MATCH_DEFAULT && zext(c)->update_acl_match == ACL_MATCH_DEFAULT);
        CHECK(a && !zext(a)->db_acl_ceiling && !a->ext_shared);
        free_server_config_fields(&cfg);
    }
    /* a string statement written twice: the later value counts and the earlier one is freed (it leaked before B7a) */
    if (parse_ok("key \"k2\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTI=\"; };"
                 "zone \"d.test\" { type slave; file \"d1\"; file \"d2\"; tsig-key \"k1\"; tsig-key \"k2\"; "
                 "file-format bind; file-format tinydns; notify-source \"192.0.2.1\"; notify-source \"192.0.2.2\"; "
                 "masters { 192.0.2.9; }; };", &cfg)) {
        const zone_config_t *d = first_zone(&cfg);
        CHECK(d && d->file && strcmp(d->file, "d2") == 0);
        CHECK(d && zext(d)->tsig_key && strcmp(zext(d)->tsig_key, "k2") == 0);
        CHECK(d && zext(d)->file_format && strcmp(zext(d)->file_format, "tinydns") == 0);
        CHECK(d && zext(d)->notify_source && strcmp(zext(d)->notify_source, "192.0.2.2") == 0);
        free_server_config_fields(&cfg);
    }
    expect_reject("transfer-acl-match both","zone \"a.test\" { type master; file \"a\"; transfer-acl-match both; };");
    expect_reject("update-acl-match missing value", "zone \"a.test\" { type master; file \"a\"; update-acl-match; };");
    expect_reject("transfer-acl-match no semicolon", "zone \"a.test\" { type master; file \"a\"; transfer-acl-match any };");
    expect_reject("transfer-acl-match in options", "options { transfer-acl-match any; }; zone \"a.test\" { type master; file \"a\"; transfer-acl-match x; };");

    /* the restricted parse accepts everything the loader can write */
    {
        char err[200];
        zone_ext_shared_t *sh = db_parse_quiet(
            "allow-transfer { 192.0.2.1; 2001:db8::/32; !198.51.100.0/24; key \"xfr\"; }; also-notify { 192.0.2.53 port 5300; 2001:db8::53; }; "
            "allow-update { 192.0.2.9; key \"upd\"; }; tsig-key \"m\"; notify-retries 3; notify-retry-interval 30; "
            "notify-retry-backoff exponential; ixfr-history 8; additional-from-auth in-domain; disable-auto-tc-flag yes; "
            "zone-udp-bufsize 1232; zone-tcp-mss 1400; zone-tcp-window 64k; zone-tcp-sndbuf 65536; transfer-acl-match any; "
            "update-acl-match all; # trailing comment", err, sizeof(err));
        CHECK(sh != NULL);
        if (sh) {
            const zone_ext_t *x = &sh->ext;
            CHECK(x->allow_transfer_count == 3 && x->tsig_keys_count == 1 && strcmp(x->tsig_keys[0], "xfr") == 0);
            CHECK(x->allow_transfer_parsed != NULL && x->allow_update_parsed != NULL && x->allow_update_count == 2);
            CHECK(x->also_notify_count == 2 && x->also_notify[0].port == 5300 && x->also_notify[1].port == 53);
            CHECK(x->tsig_key && strcmp(x->tsig_key, "m") == 0 && x->ixfr_history_set && x->ixfr_history == 8);
            CHECK(x->notify_retry.retries == 3 && x->notify_retry.interval == 30 && x->notify_retry.backoff == NOTIFY_BACKOFF_EXPONENTIAL);
            CHECK(x->disable_auto_tc_flag && x->additional_from_auth_specified && x->additional_from_auth == ADDITIONAL_AUTH_IN_DOMAIN);
            CHECK(x->zone_udp_bufsize == 1232 && x->zone_tcp_mss == 1400 && x->zone_tcp_window == 65536 && x->zone_tcp_sndbuf == 65536);
            CHECK(x->transfer_acl_match == ACL_MATCH_ANY && x->update_acl_match == ACL_MATCH_ALL && x->db_acl_ceiling);
            CHECK(atomic_load(&sh->refs) == 1);
            zone_ext_shared_unref(sh);
        }
        /* an empty text (a zone whose metadata give nothing, a profile with no statements) is settings with nothing set */
        sh = db_parse_quiet("", err, sizeof(err));
        CHECK(sh != NULL && sh->ext.allow_transfer_count == 0 && sh->ext.db_acl_ceiling);
        zone_ext_shared_unref(sh);
        sh = db_parse_quiet("  # only a comment", err, sizeof(err));
        CHECK(sh != NULL);
        zone_ext_shared_unref(sh);
        /* a profile text followed by the zone's text: the later statement replaces the earlier one (statement level) */
        sh = db_parse_quiet("allow-transfer { 192.0.2.1; }; ixfr-history 3; also-notify { 192.0.2.7; };\n"
                            "allow-transfer { 192.0.2.2; key \"k\"; }; also-notify { 192.0.2.8; 192.0.2.9; };", err, sizeof(err));
        CHECK(sh != NULL);
        if (sh) {
            CHECK(sh->ext.allow_transfer_count == 1 && strcmp(sh->ext.allow_transfer[0], "192.0.2.2") == 0);
            CHECK(sh->ext.tsig_keys_count == 1 && sh->ext.ixfr_history == 3 && sh->ext.also_notify_count == 2);
            zone_ext_shared_unref(sh);
        }
        sh = db_parse_quiet("allow-transfer { key \"a\"; }; allow-transfer { 192.0.2.2; };", err, sizeof(err));
        CHECK(sh != NULL && sh->ext.tsig_keys_count == 0 && sh->ext.allow_transfer_count == 1);   /* the key of the replaced statement is gone */
        zone_ext_shared_unref(sh);
        sh = db_parse_quiet("tsig-key \"a\"; tsig-key \"b\";", err, sizeof(err));
        CHECK(sh != NULL && strcmp(sh->ext.tsig_key, "b") == 0);
        zone_ext_shared_unref(sh);
    }
    /* ... and refuses everything else */
    expect_db_reject("file \"/etc/passwd\";", "not allowed");
    expect_db_reject("type slave;", "not allowed");
    /* (masters and primaries are accepted since B7b: test_acl_ceiling_match_and_masters) */
    expect_db_reject("program \"/bin/sh\";", "not allowed");
    expect_db_reject("program-args { \"-c\"; };", "not allowed");
    expect_db_reject("program-user \"root\";", "not allowed");
    expect_db_reject("forwarders { 192.0.2.1; };", "not allowed");
    expect_db_reject("rate-limit { responses-per-second 1; };", "not allowed");
    expect_db_reject("ecs-tags { };", "not allowed");
    expect_db_reject("catalog-zone yes;", "not allowed");
    expect_db_reject("file-format tinydns;", "not allowed");
    expect_db_reject("notify-source 192.0.2.1;", "not allowed");
    expect_db_reject("allow-query { any; };", "not allowed");              /* a BIND option: refused, not skipped */
    expect_db_reject("no-such-statement 1;", "not allowed");
    expect_db_reject("include \"/etc/passwd\";", "include");
    expect_db_reject("zone \"x.test\" { };", "not allowed");
    expect_db_reject("allow-transfer { corp-net; };", "not an address");     /* named ACLs of karidns.conf are not reachable */
    expect_db_reject("allow-transfer { localnets; };", "not an address");
    expect_db_reject("allow-transfer { 300.1.1.1; };", "not an address");
    expect_db_reject("allow-update { !key \"k\"; };", NULL);
    expect_db_reject("also-notify { example.test; };", "not an IP");
    expect_db_reject("ixfr-history 99;", NULL);
    expect_db_reject("zone-udp-bufsize 100;", NULL);
    expect_db_reject("notify-retry-backoff sometimes;", NULL);
    expect_db_reject("transfer-acl-match maybe;", NULL);
    expect_db_reject("allow-transfer { 192.0.2.1; }", NULL);                /* no semicolon */
    expect_db_reject("allow-transfer { 192.0.2.1; ", NULL);                 /* unbalanced */
    expect_db_reject("allow-transfer { 192.0.2.1; }; };", "brace");          /* a stray } would end the block early */
    expect_db_reject("ixfr-history 3; }; allow-transfer { any; };", NULL);
    expect_db_reject("/* open comment", NULL);                               /* the closing brace added by the parser is inside it */
    expect_db_reject("tsig-key", NULL);

    /* key names: db_settings_missing_key() against the keys of the configuration */
    snprintf(txt, sizeof(txt), "key \"xfr\" { algorithm hmac-sha256; secret \"%s\"; }; key \"upd\" { algorithm hmac-sha256; secret \"%s\"; };"
             "options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling { 192.0.2.0/24; key \"xfr\"; }; }; };",
             SECRET_OK, SECRET_OK);
    server_config_t kc;
    if (parse_ok(txt, &kc)) {
        char err[200];
        zone_ext_shared_t *sh = db_parse_quiet("allow-transfer { key \"xfr\"; key \"XFR.\"; }; allow-update { key \"upd\"; 192.0.2.1; none; };", err, sizeof(err));
        CHECK(sh && db_settings_missing_key(&sh->ext, &kc) == NULL);        /* names are DNS names: case and the final dot do not matter */
        zone_ext_shared_unref(sh);
        sh = db_parse_quiet("allow-transfer { key \"xfr\"; key \"nope\"; };", err, sizeof(err));
        CHECK(sh && db_settings_missing_key(&sh->ext, &kc) && strcmp(db_settings_missing_key(&sh->ext, &kc), "nope") == 0);
        zone_ext_shared_unref(sh);
        sh = db_parse_quiet("allow-update { key \"ghost\"; };", err, sizeof(err));
        CHECK(sh && db_settings_missing_key(&sh->ext, &kc) && strcmp(db_settings_missing_key(&sh->ext, &kc), "ghost") == 0);
        zone_ext_shared_unref(sh);
        sh = db_parse_quiet("tsig-key \"ghost\";", err, sizeof(err));
        CHECK(sh && db_settings_missing_key(&sh->ext, &kc) != NULL);
        zone_ext_shared_unref(sh);
        CHECK(db_acl_ceiling_configured(&kc));
        free_server_config_fields(&kc);
    }
    if (parse_ok("options { database { driver sqlite3; database-file \"/x.db\"; }; };", &kc)) {
        CHECK(!db_acl_ceiling_configured(&kc));
        free_server_config_fields(&kc);
    }

    /* ACL evaluation.  Ceiling: 192.0.2.0/24 or a request signed with "xfr". */
    server_config_t cc, nc;
    snprintf(txt, sizeof(txt), "key \"xfr\" { algorithm hmac-sha256; secret \"%s\"; }; key \"upd\" { algorithm hmac-sha256; secret \"%s\"; };"
             "options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling { 192.0.2.0/24; key \"xfr\"; }; }; };",
             SECRET_OK, SECRET_OK);
    bool have_cc = parse_ok(txt, &cc);
    snprintf(txt, sizeof(txt), "key \"xfr\" { algorithm hmac-sha256; secret \"%s\"; };"
             "options { database { driver sqlite3; database-file \"/x.db\"; }; };", SECRET_OK);
    bool have_nc = parse_ok(txt, &nc);
    if (have_cc && have_nc) {
        zone_config_t *z;
        /* DB ACL with addresses only: the ceiling must also let the client in */
        z = db_zone_from("allow-transfer { 192.0.2.0/24; };");
        CHECK(z && zone_transfer_acl_allows(&cc, z, "192.0.2.9", NULL));
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "198.51.100.1", NULL));                   /* not in the DB ACL */
        CHECK(z && !zone_transfer_acl_allows(&nc, z, "192.0.2.9", NULL));                      /* no ceiling: refused */
        CHECK(z && !zone_update_acl_allows(&cc, z, "192.0.2.9", NULL));                        /* no allow-update at all */
        free_zone_config(z);
        z = db_zone_from("allow-transfer { 198.51.100.0/24; };");
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "198.51.100.7", NULL));                   /* DB allows, the ceiling does not */
        CHECK(z && zone_transfer_acl_allows(&cc, z, "198.51.100.7", "xfr"));                   /* inside the ceiling by its key */
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "198.51.100.7", "upd"));                  /* a key the ceiling does not list */
        free_zone_config(z);
        z = db_zone_from("allow-transfer { any; };");                                          /* a hostile loader: bounded by the ceiling */
        CHECK(z && zone_transfer_acl_allows(&cc, z, "192.0.2.77", NULL) && !zone_transfer_acl_allows(&cc, z, "203.0.113.5", NULL));
        CHECK(z && !zone_transfer_acl_allows(&nc, z, "192.0.2.77", NULL));
        free_zone_config(z);
        /* address + key: default = both, transfer-acl-match any = either (PowerDNS) */
        z = db_zone_from("allow-transfer { 192.0.2.0/24; key \"xfr\"; };");
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "192.0.2.1", NULL) && zone_transfer_acl_allows(&cc, z, "192.0.2.1", "xfr"));
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "198.51.100.1", "xfr"));
        free_zone_config(z);
        z = db_zone_from("allow-transfer { 192.0.2.0/24; key \"xfr\"; }; transfer-acl-match any;");
        CHECK(z && zone_transfer_acl_allows(&cc, z, "192.0.2.1", NULL) && zone_transfer_acl_allows(&cc, z, "192.0.2.1", "xfr"));
        CHECK(z && zone_transfer_acl_allows(&cc, z, "198.51.100.1", "xfr") && !zone_transfer_acl_allows(&cc, z, "198.51.100.1", NULL));
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "198.51.100.1", "upd"));
        CHECK(z && !zone_transfer_acl_allows(&nc, z, "192.0.2.1", "xfr"));
        free_zone_config(z);
        /* a key the configuration does not define closes the whole transfer ACL */
        z = db_zone_from("allow-transfer { 192.0.2.0/24; key \"gone\"; }; transfer-acl-match any;");
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "192.0.2.1", NULL) && !zone_transfer_acl_allows(&cc, z, "192.0.2.1", "xfr"));
        free_zone_config(z);
        /* the zone's tsig-key (AXFR-MASTER-TSIG) is the key of its primary, not a key that may transfer */
        z = db_zone_from("tsig-key \"xfr\";");
        CHECK(z && !zone_transfer_acl_allows(&cc, z, "192.0.2.1", "xfr"));
        free_zone_config(z);
        z = db_zone_from("tsig-key \"xfr\"; allow-transfer { 192.0.2.1; };");
        CHECK(z && zone_transfer_acl_allows(&cc, z, "192.0.2.1", NULL) && !zone_transfer_acl_allows(&cc, z, "192.0.2.2", "xfr"));
        free_zone_config(z);
        /* update: default = the address matches or the key is named; update-acl-match all = every kind that is written */
        z = db_zone_from("allow-update { 192.0.2.0/24; key \"xfr\"; };");
        CHECK(z && zone_update_acl_allows(&cc, z, "192.0.2.1", NULL) && zone_update_acl_allows(&cc, z, "198.51.100.1", "xfr"));
        CHECK(z && !zone_update_acl_allows(&cc, z, "198.51.100.1", NULL) && !zone_update_acl_allows(&cc, z, "198.51.100.1", "upd"));
        free_zone_config(z);
        z = db_zone_from("allow-update { 192.0.2.0/24; key \"xfr\"; }; update-acl-match all;");
        CHECK(z && !zone_update_acl_allows(&cc, z, "192.0.2.1", NULL) && zone_update_acl_allows(&cc, z, "192.0.2.1", "xfr"));
        CHECK(z && !zone_update_acl_allows(&cc, z, "198.51.100.1", "xfr") && !zone_update_acl_allows(&cc, z, "192.0.2.1", "upd"));
        CHECK(z && !zone_update_acl_allows(&nc, z, "192.0.2.1", "xfr"));
        free_zone_config(z);
        z = db_zone_from("allow-update { 192.0.2.0/24; }; update-acl-match all;");           /* one kind: the mode does not matter */
        CHECK(z && zone_update_acl_allows(&cc, z, "192.0.2.5", NULL) && zone_update_acl_allows(&cc, z, "192.0.2.5", "upd"));
        free_zone_config(z);
        z = db_zone_from("allow-update { key \"upd\"; }; update-acl-match all;");            /* a key the ceiling does not list */
        CHECK(z && !zone_update_acl_allows(&cc, z, "198.51.100.5", "upd"));
        free_zone_config(z);
        z = db_zone_from("allow-update { key \"ghost\"; 192.0.2.0/24; };");
        CHECK(z && !zone_update_acl_allows(&cc, z, "192.0.2.5", NULL));                       /* undefined key: closed */
        free_zone_config(z);
        z = db_zone_from("allow-update { none; };");
        CHECK(z && !zone_update_acl_allows(&cc, z, "192.0.2.5", NULL) && !zone_update_acl_allows(&cc, z, "192.0.2.5", "xfr"));
        free_zone_config(z);

        /* file zones keep their meaning, and the ceiling does not apply to them */
        snprintf(txt, sizeof(txt), "key \"k1\" { algorithm hmac-sha256; secret \"%s\"; };"
                 "options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling { 10.0.0.0/8; }; }; };"
                 "zone \"t1.test\" { type master; file \"t1\"; allow-transfer { 192.0.2.1; key k1; }; allow-update { 192.0.2.1; key k1; }; };"
                 "zone \"t2.test\" { type master; file \"t2\"; allow-transfer { 192.0.2.1; key k1; }; transfer-acl-match any; "
                 "allow-update { 192.0.2.1; key k1; }; update-acl-match all; };"
                 "zone \"t3.test\" { type master; file \"t3\"; tsig-key k1; };", SECRET_OK);
        server_config_t fc;
        if (parse_ok(txt, &fc)) {
            const zone_config_t *t1 = first_zone(&fc), *t2 = t1 ? t1->next : NULL, *t3 = t2 ? t2->next : NULL;
            CHECK(t1 && t2 && t3);
            if (t1 && t2 && t3) {
                CHECK(zone_transfer_acl_allows(&fc, t1, "192.0.2.1", "k1") && !zone_transfer_acl_allows(&fc, t1, "192.0.2.1", NULL));
                CHECK(!zone_transfer_acl_allows(&fc, t1, "198.51.100.1", "k1"));
                CHECK(zone_update_acl_allows(&fc, t1, "192.0.2.1", NULL) && zone_update_acl_allows(&fc, t1, "198.51.100.1", "k1"));
                CHECK(!zone_update_acl_allows(&fc, t1, "198.51.100.1", NULL));
                CHECK(zone_transfer_acl_allows(&fc, t2, "192.0.2.1", NULL) && zone_transfer_acl_allows(&fc, t2, "198.51.100.1", "k1"));
                CHECK(!zone_transfer_acl_allows(&fc, t2, "198.51.100.1", NULL));
                CHECK(!zone_update_acl_allows(&fc, t2, "192.0.2.1", NULL) && zone_update_acl_allows(&fc, t2, "192.0.2.1", "k1"));
                CHECK(!zone_update_acl_allows(&fc, t2, "198.51.100.1", "k1"));
                CHECK(zone_transfer_acl_allows(&fc, t3, "198.51.100.1", "k1") && !zone_transfer_acl_allows(&fc, t3, "198.51.100.1", NULL));
            }
            free_server_config_fields(&fc);
        }
    }
    if (have_cc) free_server_config_fields(&cc);
    if (have_nc) free_server_config_fields(&nc);

    /* interned objects are reference counted: the last reference frees it, a zone config holds one */
    {
        char err[200];
        zone_ext_shared_t *sh = db_parse_quiet("allow-transfer { 192.0.2.1; };", err, sizeof(err));
        CHECK(sh != NULL);
        zone_config_t *z = calloc(1, sizeof(*z));
        z->domain = strdup("r.test.");
        z->type = strdup("master");
        z->ext = &zone_ext_shared_ref(sh)->ext;
        z->ext_shared = true;
        CHECK(atomic_load(&sh->refs) == 2);
        zone_ext_shared_unref(sh);
        CHECK(atomic_load(&sh->refs) == 1 && z->ext->allow_transfer_count == 1);
        free_zone_config(z);                                  /* the last reference: ASan/LSan would see a leak or a use after free */
    }
}

/* ------------------------------------------------------------------------ */
/* B7b: acl-ceiling-match (any = address OR key, all = address AND key; one kind of entry: that kind decides), and
 * masters / primaries in the settings of a database zone (a SLAVE / CONSUMER) and in zone { } of karidns.conf */
static void test_acl_ceiling_match_and_masters(void) {
    printf("[TEST] acl-ceiling-match, masters / primaries in DB settings and in zones...\n");
    char txt[2048];
    server_config_t cfg;
    if (parse_ok("options { database { driver sqlite3; database-file \"/x.db\"; }; };", &cfg)) {
        CHECK(cfg.database.acl_ceiling_match == ACL_MATCH_DEFAULT);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling-match all; }; };", &cfg)) {
        CHECK(cfg.database.acl_ceiling_match == ACL_MATCH_ALL);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling-match ANY; }; };", &cfg)) {
        CHECK(cfg.database.acl_ceiling_match == ACL_MATCH_ANY);
        free_server_config_fields(&cfg);
    }
    expect_reject("acl-ceiling-match both", "options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling-match both; }; };");
    expect_reject("acl-ceiling-match no value", "options { database { driver sqlite3; database-file \"/x.db\"; acl-ceiling-match; }; };");

    /* evaluation: ceiling { 192.0.2.0/24; key xfr; } with any / all, and ceilings with one kind of entry */
    static const char *const ceil_any = "acl-ceiling { 192.0.2.0/24; key \"xfr\"; };";
    struct { const char *ceiling_stmt; const char *mode; } v[] = {
        { ceil_any, "" }, { ceil_any, "acl-ceiling-match any;" }, { ceil_any, "acl-ceiling-match all;" },
        { "acl-ceiling { 192.0.2.0/24; };", "acl-ceiling-match all;" }, { "acl-ceiling { key \"xfr\"; };", "acl-ceiling-match all;" },
        { "acl-ceiling { 192.0.2.0/24; };", "" }, { "acl-ceiling { key \"xfr\"; };", "" },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        snprintf(txt, sizeof(txt), "key \"xfr\" { algorithm hmac-sha256; secret \"%s\"; }; key \"oth\" { algorithm hmac-sha256; secret \"%s\"; };"
                 "options { database { driver sqlite3; database-file \"/x.db\"; %s %s }; };", SECRET_OK, SECRET_OK, v[i].ceiling_stmt, v[i].mode);
        server_config_t c;
        if (!parse_ok(txt, &c)) continue;
        zone_config_t *z = db_zone_from("allow-transfer { any; };");        /* the zone's own ACL lets everybody in: the ceiling decides */
        bool all = strstr(v[i].mode, "all") != NULL;
        bool both = strstr(v[i].ceiling_stmt, "192.0.2") && strstr(v[i].ceiling_stmt, "key");
        bool has_addr = strstr(v[i].ceiling_stmt, "192.0.2") != NULL, has_key = strstr(v[i].ceiling_stmt, "key") != NULL;
        bool in_addr_only = z && zone_transfer_acl_allows(&c, z, "192.0.2.9", NULL);                 /* address inside, no key */
        bool in_key_only = z && zone_transfer_acl_allows(&c, z, "198.51.100.9", "xfr");              /* address outside, ceiling key */
        bool in_both = z && zone_transfer_acl_allows(&c, z, "192.0.2.9", "xfr");
        bool in_neither = z && zone_transfer_acl_allows(&c, z, "198.51.100.9", NULL);
        bool in_other_key = z && zone_transfer_acl_allows(&c, z, "198.51.100.9", "oth");
        bool in_addr_other_key = z && zone_transfer_acl_allows(&c, z, "192.0.2.9", "oth");
        bool and_mode = all && both;
        CHECK_MSG(in_both, "variant %zu: inside by both", i);
        CHECK_MSG(!in_neither && !in_other_key, "variant %zu: outside", i);
        CHECK_MSG(in_addr_only == (has_addr && !and_mode), "variant %zu: address only -> %d", i, (int)in_addr_only);
        CHECK_MSG(in_key_only == (has_key && !and_mode), "variant %zu: key only -> %d", i, (int)in_key_only);
        CHECK_MSG(in_addr_other_key == (has_addr && !and_mode), "variant %zu: address and a key the ceiling does not list -> %d", i, (int)in_addr_other_key);
        free_zone_config(z);
        /* the same for updates, and a zone ACL narrower than the ceiling stays narrower */
        z = db_zone_from("allow-update { 192.0.2.0/24; };");
        CHECK_MSG(z && zone_update_acl_allows(&c, z, "192.0.2.9", "xfr"), "variant %zu: update by both", i);
        CHECK_MSG(z && zone_update_acl_allows(&c, z, "192.0.2.9", NULL) == (has_addr && !and_mode), "variant %zu: update by address", i);
        free_zone_config(z);
        z = db_zone_from("allow-transfer { 203.0.113.0/24; };");
        CHECK_MSG(z && !zone_transfer_acl_allows(&c, z, "192.0.2.9", "xfr"), "variant %zu: the zone's ACL does not list it", i);
        CHECK_MSG(z && zone_transfer_acl_allows(&c, z, "203.0.113.9", "xfr") == (has_key && !and_mode ? true : and_mode ? false : false),
                  "variant %zu: ACL address outside the address part of the ceiling", i);
        free_zone_config(z);
        free_server_config_fields(&c);
    }

    /* masters and primaries in the restricted settings text */
    char err[200];
    zone_ext_shared_t *sh = db_parse_quiet("masters { 192.0.2.1 port 5300; 2001:db8::1; }; tsig-key \"k\";", err, sizeof(err));
    CHECK(sh && sh->ext.masters_count == 2 && sh->ext.masters[0].port == 5300 && sh->ext.masters[1].port == 53 && sh->ext.masters_parsed);
    if (sh) zone_ext_shared_unref(sh);
    sh = db_parse_quiet("primaries { 192.0.2.7; };", err, sizeof(err));
    CHECK(sh && sh->ext.masters_count == 1 && strcmp(sh->ext.masters[0].ip, "192.0.2.7") == 0);
    if (sh) zone_ext_shared_unref(sh);
    /* a later statement replaces an earlier one (a profile first, the zone after it), masters and primaries are one statement */
    sh = db_parse_quiet("masters { 192.0.2.1; 192.0.2.2; }; primaries { 192.0.2.9 port 54; };", err, sizeof(err));
    CHECK(sh && sh->ext.masters_count == 1 && strcmp(sh->ext.masters[0].ip, "192.0.2.9") == 0 && sh->ext.masters[0].port == 54);
    if (sh) zone_ext_shared_unref(sh);
    expect_db_reject("masters { ns1.example.net; };", "not an IP address");
    expect_db_reject("masters { 192.0.2.1 port 0; };", NULL);
    expect_db_reject("masters { 192.0.2.1 port 99999; };", NULL);
    expect_db_reject("masters { 192.0.2.1 }; ", NULL);
    expect_db_reject("masters { 192.0.2.1; ", NULL);
    expect_db_reject("masters 192.0.2.1;", NULL);
    {
        char many[1200] = "masters {";
        for (int i = 1; i <= 33; i++) {
            char one[24];
            snprintf(one, sizeof(one), " 192.0.2.%d;", i);
            strcat(many, one);
        }
        strcat(many, " };");
        expect_db_reject(many, "more than 32");
        sh = db_parse_quiet(many + 0, err, sizeof(err));
        CHECK(sh == NULL);
        strcpy(strstr(many, " 192.0.2.33;"), " };");
        sh = db_parse_quiet(many, err, sizeof(err));
        CHECK(sh && sh->ext.masters_count == 32);
        if (sh) zone_ext_shared_unref(sh);
    }
    expect_db_reject("type slave; masters { 192.0.2.1; };", "statement 'type' is not allowed");
    expect_db_reject("masters { 192.0.2.1; }; file \"/etc/passwd\";", "statement 'file' is not allowed");

    /* karidns.conf: primaries is the BIND 9.16+ name of masters */
    if (parse_ok("zone \"s.test\" { type secondary; primaries { 192.0.2.1 port 5353; }; };"
                 "zone \"t.test\" { type slave; masters { 192.0.2.2; }; };", &cfg)) {
        const zone_config_t *s = first_zone(&cfg), *t = s ? s->next : NULL;
        CHECK(s && zext(s)->masters_count == 1 && zext(s)->masters[0].port == 5353 && strcmp(zext(s)->masters[0].ip, "192.0.2.1") == 0);
        CHECK(t && zext(t)->masters_count == 1 && strcmp(zext(t)->masters[0].ip, "192.0.2.2") == 0);
        free_server_config_fields(&cfg);
    }
}

/* B9a: alias-resolver { <ip> [port <n>]; ... }; in options, in a zone, and in the settings text of a database zone */
static void test_alias_resolver_option(void) {
    printf("[TEST] alias-resolver in options, zones and database settings (B9a)...\n");
    server_config_t cfg;
    if (parse_ok("options { alias-resolver { 192.0.2.53; 2001:db8::53 port 5353; }; };", &cfg)) {
        CHECK(cfg.alias_resolvers_count == 2);
        CHECK_STR(cfg.alias_resolvers[0].ip, "192.0.2.53");
        CHECK(cfg.alias_resolvers[0].port == 53 && cfg.alias_resolvers[1].port == 5353);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { alias-resolver { 192.0.2.1; }; alias-resolver { 192.0.2.2; }; };", &cfg)) {   /* a later statement replaces */
        CHECK(cfg.alias_resolvers_count == 1 && strcmp(cfg.alias_resolvers[0].ip, "192.0.2.2") == 0);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"z.test.\" { type primary; file \"z.zone\"; alias-resolver { 192.0.2.7 port 5300; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && zext(z)->alias_resolvers_count == 1 && zext(z)->alias_resolvers[0].port == 5300);
        free_server_config_fields(&cfg);
    }
    expect_reject("alias-resolver with a host name", "options { alias-resolver { ns.example.test; }; };");
    expect_reject("alias-resolver with a bad port", "options { alias-resolver { 192.0.2.1 port 0; }; };");
    expect_reject("alias-resolver without braces", "options { alias-resolver 192.0.2.1; };");
    expect_reject("zone alias-resolver with a host name", "zone \"z.test.\" { type primary; file \"z\"; alias-resolver { example.test; }; };");
    expect_reject("alias-resolver with nine entries",
                  "options { alias-resolver { 192.0.2.1; 192.0.2.2; 192.0.2.3; 192.0.2.4; 192.0.2.5; 192.0.2.6; 192.0.2.7; 192.0.2.8; 192.0.2.9; }; };");
    /* the settings text of a database zone (the loader and karidns_profiles write this statement): the later statement replaces */
    char err[200];
    zone_ext_shared_t *sh = db_parse_quiet("alias-resolver { 192.0.2.1; }; alias-resolver { 192.0.2.9 port 54; };", err, sizeof(err));
    CHECK(sh != NULL);
    if (sh) {
        CHECK(sh->ext.alias_resolvers_count == 1 && strcmp(sh->ext.alias_resolvers[0].ip, "192.0.2.9") == 0 && sh->ext.alias_resolvers[0].port == 54);
        zone_ext_shared_unref(sh);
    }
    expect_db_reject("alias-resolver { example.test; };", NULL);
}

int main(void) {
    printf("=== Starting Config Directive Tests ===\n");
    test_defaults();
    test_boolean_directives();
    test_numeric_directives();
    test_numeric_directives_invalid();
    test_buffer_sizes();
    test_transport_params();
    test_notify_retry();
    test_ixfr_history_option();
    test_additional_from_auth();
    test_options_syntax_errors();
    test_ecs_and_location_tags();
    test_ecs_trusted_resolvers();
    test_dnstap_block();
    test_database_block();
    test_zone_types_and_files();
    test_zone_program_and_forward();
    test_zone_rate_limit();
    test_acl_lists();
    test_tsig_key_blocks();
    test_control_channel();
    test_logging_channels();
    test_structure_and_validation();
    test_config_cidr_matching();
    test_config_negative_patterns();
    test_boolean_statements_everywhere();
    test_logging_category_lists();
    test_zone_type_case();
    test_named_acls();
    test_alias_resolver_option();
    test_zone_config_index();
    test_zone_ext_layout();
    test_zone_flat_list_removed();
    test_db_settings_and_acl_match();
    test_db_ecs_trusted();
    test_acl_ceiling_match_and_masters();

    printf("[*] %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("=== Config Directive Tests FAILED ===\n");
        return 1;
    }
    printf("=== All Config Directive Tests PASSED ===\n");
    return 0;
}

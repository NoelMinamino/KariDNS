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
#include <syslog.h>

#include "../dns_config_parser.h"
#include "test_zext.h"
#include "../dns_utils.h"
#include "../dns_tsig_acl.h"
#include "../dns_zone_parser.h"

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

    if (parse_ok("options { tcp-initial-timeout 1500ms; tcp-idle-timeout 4294967295ms; };", &cfg)) {
        CHECK(cfg.tcp_initial_timeout == 1500);
        CHECK(cfg.tcp_idle_timeout == 4294967295u);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { port 5353; tcp-idle-timeout 0ms; query-log-max-qps 250; "
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
    expect_reject("unknown zone type", "zone \"example.com\" { type hint_; file \"z\"; };");   /* hint itself is skipped with a warning (test_bind_compat_paths) */
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

    /* an unknown property inside key{} is a configuration error (it used to be skipped; see test_strict_options_and_key) */
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; comment { x; }; secret \"%s\"; };", SECRET_OK);
    expect_reject("unknown property inside key", txt);

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
    /* an unknown key is a configuration error (a misspelt "secret" must not leave the channel open or on the default socket) */
    expect_reject("unknown key with a block", "control-channel { future-option { a; }; };");
    expect_reject("unknown key 'port'", "control-channel { port 953; };");
    expect_reject("unknown key 'bind-address'", "control-channel { bind-address 127.0.0.1; };");
    expect_reject("unknown key 'enabled'", "control-channel { enabled yes; };");
    snprintf(txt, sizeof(txt), "control-channel { socket \"/x\"; secrt \"%s\"; };", SECRET_OK);
    expect_reject("misspelt secret", txt);

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
            CHECK(q->time_fmt == LOGTIME_LOCAL && q->print_category == true && q->print_severity == false);
            CHECK(q->max_qps == 100 && q->max_qps_specified == true);
        }
        if (r) {
            CHECK(r->size_limit == 512ULL * 1024);
            CHECK(r->print_severity == true && r->time_fmt == LOGTIME_NONE);
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
    /* invalid size / versions / max-qps values are errors (they used to be reported and ignored); so are unknown statements and a channel
     * with two destinations (BIND: "exactly one of file, syslog, null, and stderr must be present") */
    expect_reject("negative size", "logging { channel \"x\" { file \"/x\" size -5; }; };");
    expect_reject("size is text", "logging { channel \"y\" { file \"/y\" size abc; }; };");
    expect_reject("size is a unit only", "logging { channel \"z\" { file \"/z\" size k; }; };");
    expect_reject("negative versions", "logging { channel \"z\" { file \"/z\" versions -2; }; };");
    expect_reject("max-qps is text", "logging { channel \"m\" { file \"/m\"; max-qps abc; }; };");
    expect_reject("unknown statement in logging", "logging { severity dynamic; channel \"c\" { file \"/c\"; }; };");
    expect_reject("two destinations", "logging { channel \"c\" { syslog daemon; file \"/c\"; }; };");

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
        CHECK(c && c->time_fmt == LOGTIME_LOCAL && c->print_category == true && c->print_severity == true);
        free_server_config_fields(&cfg);
    }
    expect_reject("print-time maybe", "logging { channel q { file \"/tmp/q.log\"; print-time maybe; }; };");
}

static void test_logging_category_lists(void) {
    printf("[TEST] category with several channels (BIND writes to all of them)...\n");
    server_config_t cfg;
    if (parse_ok("logging { channel a { file \"/tmp/a.log\"; }; channel b { file \"/tmp/b.log\"; };"
                 "  category queries { a; b; }; category responses { b; a; }; };", &cfg)) {
        CHECK_STR(cfg.logging.queries_channel_name, "a");
        CHECK(cfg.logging.queries_channel && strcmp(cfg.logging.queries_channel->name, "a") == 0);
        CHECK_STR(cfg.logging.responses_channel_name, "b");
        CHECK(cfg.logging.cat[LOGC_QUERIES].n == 2 && strcmp(cfg.logging.cat[LOGC_QUERIES].name[1], "b") == 0);
        CHECK(cfg.logging.queries_enabled && cfg.logging.responses_enabled);
        free_server_config_fields(&cfg);
    }
    /* a second statement for a category adds channels (isc_log_usechannel() appends); an empty list adds none */
    if (parse_ok("logging { channel a { file \"/tmp/a.log\"; }; channel b { file \"/tmp/b.log\"; };"
                 "category queries { a; }; category queries { b; }; category queries { }; };", &cfg)) {
        CHECK(cfg.logging.cat[LOGC_QUERIES].n == 2);
        CHECK_STR(cfg.logging.queries_channel_name, "a");
        free_server_config_fields(&cfg);
    }
    /* only an empty list: the category is not configured, the query log stays off */
    if (parse_ok("logging { category queries { }; };", &cfg)) {
        CHECK(cfg.logging.queries_channel_name == NULL && cfg.logging.queries_channel == NULL);
        CHECK(!cfg.logging.queries_enabled);
        free_server_config_fields(&cfg);
    }
    expect_reject("a channel that is not defined", "logging { channel a { file \"/tmp/a.log\"; }; category queries { a; undefined_b; }; };");
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
    /* localhost and localnets are built-in names now (tests/test_acl_match.c); an acl block cannot be named like them */
    expect_reject("acl named localhost", "acl localhost { 192.0.2.1; };");
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
        /* zone_settings_render() (what a primary sends a secondary): of a database zone's allow-transfer only what lies inside the
         * ceiling is written; a key counts when the ceiling lists it (ceiling_has_key); nothing left, or no ceiling, gives none */
        {
            char out[2048];
            z = db_zone_from("allow-transfer { 192.0.2.0/24; 198.51.100.0/24; key \"xfr\"; key \"upd\"; };");
            size_t rn = z ? zone_settings_render(&cc, z, false, out, sizeof(out)) : 0;
            CHECK(rn > 0 && rn == strlen(out));
            CHECK(strstr(out, "allow-transfer { 192.0.2.0/24; key \"xfr\"; };\n") != NULL);   /* 198.51.100.0/24 and key "upd" are cut */
            rn = z ? zone_settings_render(&nc, z, false, out, sizeof(out)) : 0;
            CHECK(rn > 0 && strstr(out, "allow-transfer { none; };\n") != NULL);
            free_zone_config(z);
            z = db_zone_from("allow-transfer { key \"upd\"; };");
            rn = z ? zone_settings_render(&cc, z, false, out, sizeof(out)) : 0;
            CHECK(rn > 0 && strstr(out, "allow-transfer { none; };\n") != NULL);
            free_zone_config(z);
        }

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

/* refusals that free what was built so far, values that are ignored with a warning, the size limit of a settings text */
static void test_refusals_and_limits(void) {
    printf("[TEST] config: refusals, ignored values, settings text limit...\n");
    server_config_t cfg;
    expect_reject("zone name with an empty label", "zone \"a..b\" { type master; file \"z\"; };");
    expect_reject("zone name with a bad escape", "zone \"a\\999.test\" { type master; file \"z\"; };");
    /* rate-limit values that are not numbers are ignored (the option keeps its default); the parse goes on */
    if (parse_ok("zone \"r.test\" { type master; file \"z\"; rate-limit { responses-per-second 20; nodata-per-second abc; "
                 "nxdomains-per-second abc; errors-per-second abc; referrals-per-second abc; all-per-second abc; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z != NULL);
        if (z) {
            const rate_limit_config_t *r = &zext(z)->rrl;
            CHECK(r->configured && r->responses_per_second == 20);
            CHECK(!r->nodata_per_second_set && !r->referrals_per_second_set);
            CHECK(r->nodata_per_second == 20);
        }
        free_server_config_fields(&cfg);
    }
    /* a negated block with separate "!" tokens inside */
    if (parse_ok("zone \"n.test\" { type master; file \"z\"; allow-transfer { !{ ! 192.0.2.1; ! any; 198.51.100.0/24; }; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z != NULL);
        if (z) CHECK_MSG(zext(z)->allow_transfer_count == 2, "%d entries", zext(z)->allow_transfer_count);
        free_server_config_fields(&cfg);
    }
    /* the text of a database zone: at most 262144 bytes, no empty key name */
    char err[200];
    size_t big = 262144 + 1;
    char *txt = malloc(big + 1);
    memset(txt, ' ', big);
    txt[big] = '\0';
    zone_ext_shared_t *sh = db_settings_parse(txt, big, err, sizeof(err));
    CHECK(sh == NULL);
    CHECK_STR(err, "settings text is too long");
    free(txt);
    expect_db_reject("allow-transfer { 192.0.2.1; key \"\"; };", "empty key name");
    expect_db_reject("tsig-key \"\";", "tsig-key");
}

/* a statement is closed by a semicolon (named.conf syntax): none of these may be taken without it, and a value of the wrong kind is refused
 * too; the parser frees what it built so far on each of these paths (run under ASan to see that) */
static void test_statements_need_a_semicolon(void) {
    printf("[TEST] config: a statement without its semicolon, a value of the wrong kind...\n");
    static const char *const bad[] = {
        "options { port 5300 };",
        "options { udp-bufsize 1232 };",
        "options { tcp-idle-timeout 10 };",
        "options { min-table-size 10 };",
        "options { max-table-size 100 };",
        "options { response-cache-size 1000 };",
        "options { nsid \"x\" };",
        "options { pid-file \"/tmp/x.pid\" };",
        "options { user \"x\" };",
        "options { group \"x\" };",
        "options { minimal-any yes };",
        "options { minimal-responses yes };",
        "options { ecs-enable yes };",
        "options { send-extended-errors yes };",
        "options { serve-stale yes };",
        "options { tcp-connection-reuse yes };",
        "options { notify-retries 3 };",
        "options { notify-retry-interval 10 };",
        "options { notify-source 192.0.2.1 };",
        "options { query-log-buffer-size 1000 };",
        "options { query-log-max-qps 5 };",
        "options { ixfr-history 5 };",
        "options { cookie-secret \"x\" };",
        "options { cookie-algorithm siphash24 };",
        "options { qps-scale 4 };",
        "options { wire-cache-max-records 5 };",
        "options { max-mqtypes 3 };",
        "options { rfc10029-mqtype yes };",
        "options { allow-program-zones yes };",
        "options { tcp-mss 1200 };",
        "options { tcp-window 5000 };",
        "options { tcp-initial-timeout 5 };",
        "options { udp-recvbuf-size 1000 };",
        "options { udp-sndbuf-size 1000 };",
        "options { bind-address { 192.0.2.1 } };",
        "options { additional-from-auth yes };",
        "options { database { driver sqlite3 } };",
        "options { database { database-file \"x\" } };",
        "options { database { poll-interval 5 } };",
        "options { database { auto-reload yes } };",
        "options { database { coalesce 5 } };",
        "options { database { loader-threads 2 } };",
        "options { database { ingest-threads 2 } };",
        "options { database { db-reload-timeout 5 } };",
        "options { database { bulk-threshold 5 } };",
        "options { database { max-zone-records 5 } };",
        "options { database { max-zone-bytes 100000 } };",
        "options { database { default-ttl 5 } };",
        "options { database { server-id \"x\" } };",
        "options { database { loader-user \"x\" } };",
        "options { database { loader-path \"x\" } };",
        "options { database { schema \"x\" } };",
        "options { database { conninfo-file \"x\" } };",
        "zone \"z.test\" { type master; file \"z\" };",
        "zone \"z.test\" { type master; file \"z\"; also-notify { 192.0.2.1 } };",
        "zone \"z.test\" { type master; file \"z\"; notify-source 192.0.2.1 };",
        "zone \"z.test\" { type master; file \"z\"; forward-timeout 5 };",
        "zone \"z.test\" { type master; file \"z\"; additional-from-auth yes };",
        "zone \"z.test\" { type master; file \"z\"; additional-from-auth maybe; };",
        "zone \"z.test\" { type master; file \"z\"; disable-auto-tc-flag yes };",
        "zone \"z.test\" { type master; file \"z\"; disable-auto-tc-flag maybe; };",
        "zone \"z.test\" { type master; file \"z\"; primary-settings yes };",
        "zone \"z.test\" { type master; file \"z\"; primary-settings maybe; };",
        "zone \"z.test\" { type master; file \"z\"; minimal-any yes };",
        "zone \"z.test\" { type master; file \"z\"; ecs-enable yes };",
        "zone \"z.test\" { type master; file \"z\"; send-extended-errors yes };",
        "zone \"z.test\" { type master; file \"z\"; serve-stale yes };",
        "zone \"z.test\" { type master; file \"z\"; ixfr-history 5 };",
        "zone \"z.test\" { type master; file \"z\"; notify-retries 3 };",
        "zone \"z.test\" { type master; file \"z\"; notify-retry-interval 10 };",
        "zone \"z.test\" { type master; file \"z\"; masters { 192.0.2.1 } };",
        "zone \"z.test\" { type master; file \"z\"; allow-update { 192.0.2.1 } };",
        "zone \"z.test\" { type master; file \"z\"; allow-transfer { 192.0.2.1 } };",
        "zone \"z.test\" { type master; file \"z\"; ecs-trusted-resolvers { 192.0.2.1 } };",
        "zone \"z.test\" { type master; file \"z\"; rate-limit { slip 5 } };",
        "zone \"z.test\" { type master; file \"z\"; rate-limit { slip 5; }; extra };",
        "zone \"z.test\" { type master; file \"z\"; zone-tcp-mss 1200 };",
        "zone \"z.test\" { type master; file \"z\"; zone-tcp-window 1200 };",
        "zone \"z.test\" { type master; file \"z\"; zone-udp-bufsize 1200 };",
        "zone \"z.test\" { type master; file \"z\"; zone-tcp-sndbuf 1200 };",
        "zone \"z.test\" { type master; file \"z\"; transfer-acl-match all };",
        "zone \"z.test\" { type master; file \"z\"; update-acl-match all };",
        "zone \"z.test\" { type master; file \"z\"; file-format \"tinydns\" };",
        "zone \"z.test\" { type master; file \"z\"; catalog-zone yes };",
        "zone \"z.test\" { type program; program \"x\" };",
        "zone \"z.test\" { type program; program \"x\"; program-user \"x\" };",
        "zone \"z.test\" { type program; program \"x\"; program-timeout 5 };",
        "zone \"z.test\" { type program; program \"x\"; program-max-failures 5 };",
        "zone \"z.test\" { type program; program \"x\"; program-args { \"a\" } };",
        "zone \"z.test\" { type forward; forwarders { 192.0.2.1 } };",
        "zone \"z.test\" { type forward; forwarders { 192.0.2.1; }; forward-timeout 5 };",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) expect_reject("missing semicolon or bad value", bad[i]);
}

/* I2: max-zone-records / max-zone-bytes in options and in a zone: the limits of one inbound AXFR/IXFR of a secondary zone */
static void test_xfr_limits_option(void) {
    printf("[TEST] max-zone-records / max-zone-bytes (options and zone, ranges as in the database block, defaults 10000000 / 1 GiB)...\n");
    server_config_t cfg;
    uint64_t r, b;
    xfr_zone_limits(NULL, NULL, &r, &b);
    CHECK(r == 10000000ull && b == (1ull << 30));
    if (parse_ok("options { };", &cfg)) {
        CHECK(cfg.max_zone_records == 10000000ull && cfg.max_zone_bytes == (1ull << 30));
        xfr_zone_limits(&cfg, NULL, &r, &b);
        CHECK(r == 10000000ull && b == (1ull << 30));
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { max-zone-records 500; max-zone-bytes 2m; };"
                 "zone \"a.example\" { type master; file \"a.zone\"; max-zone-records 20; max-zone-bytes 70000; };"
                 "zone \"b.example\" { type master; file \"b.zone\"; max-zone-records 4294967295; };"
                 "zone \"c.example\" { type master; file \"c.zone\"; };", &cfg)) {
        const zone_config_t *a = first_zone(&cfg);
        const zone_config_t *bz = a ? a->next : NULL;
        const zone_config_t *c = bz ? bz->next : NULL;
        CHECK(cfg.max_zone_records == 500 && cfg.max_zone_bytes == (2ull << 20));
        xfr_zone_limits(&cfg, a, &r, &b);
        CHECK(r == 20 && b == 70000);
        xfr_zone_limits(&cfg, bz, &r, &b);
        CHECK(r == 4294967295ull && b == (2ull << 20));           /* a zone value replaces the options one, per limit */
        xfr_zone_limits(&cfg, c, &r, &b);
        CHECK(r == 500 && b == (2ull << 20));                     /* the zone inherits options */
        free_server_config_fields(&cfg);
    }
    expect_reject("options max-zone-records 1", "options { max-zone-records 1; };");
    expect_reject("options max-zone-records above 4294967295", "options { max-zone-records 4294967296; };");
    expect_reject("options max-zone-records suffix", "options { max-zone-records 10k; };");
    expect_reject("options max-zone-records junk", "options { max-zone-records many; };");
    expect_reject("options max-zone-records missing value", "options { max-zone-records; };");
    expect_reject("options max-zone-bytes below 65535", "options { max-zone-bytes 1000; };");
    expect_reject("options max-zone-bytes above 64g", "options { max-zone-bytes 65g; };");
    expect_reject("options max-zone-bytes missing semicolon", "options { max-zone-bytes 1g };");
    expect_reject("zone max-zone-records 0", "zone \"a.example\" { type master; file \"a.zone\"; max-zone-records 0; };");
    expect_reject("zone max-zone-bytes junk", "zone \"a.example\" { type master; file \"a.zone\"; max-zone-bytes lots; };");
    expect_reject("zone max-zone-records empty", "zone \"a.example\" { type master; file \"a.zone\"; max-zone-records ; };");
}

/* ------------------------------------------------------------------------ */
/* also-notify, BIND 9.20 ARM ("also-notify", "remote-servers"): options / view / zone, `port` before the list, per-element
 * port and key, list names, the zone > view > options precedence, and errors that say where they are.  The expectations are the
 * ARM grammar  [ port <integer> ] { ( <remote-servers> | <ipv4> [ port <integer> ] | <ipv6> [ port <integer> ] ) [ key <string> ]; ... };
 * and "a zone also-notify overrides the global one". */
static int parse_capture(const char *txt, server_config_t *cfg, char *msg, size_t msglen) {
    char path[] = "/tmp/an_err_XXXXXX";
    int tmp = mkstemp(path);
    msg[0] = '\0';
    fflush(stderr);
    int saved = dup(2);
    if (tmp >= 0) dup2(tmp, 2);
    int rc = parse_named_conf(txt, cfg);
    fflush(stderr);
    if (saved >= 0) { dup2(saved, 2); close(saved); }
    if (tmp >= 0) {
        ssize_t n = pread(tmp, msg, msglen - 1, 0);
        msg[n > 0 ? n : 0] = '\0';
        close(tmp);
        unlink(path);
    }
    return rc;
}

/* the text must be refused and the message must contain every fragment of `want` (separated by '|') */
static void expect_an_error(const char *label, const char *txt, const char *want) {
    server_config_t cfg;
    char msg[2048];
    int rc = parse_capture(txt, &cfg, msg, sizeof(msg));
    g_checks++;
    if (rc != -1) {
        g_failed++;
        printf("  [FAIL] should be rejected but parsed (rc=%d): %s\n         %s\n", rc, label, txt);
        if (rc == 0) free_server_config_fields(&cfg);
        return;
    }
    char frag[256];
    const char *p = want;
    while (p && *p) {
        const char *bar = strchr(p, '|');
        size_t n = bar ? (size_t)(bar - p) : strlen(p);
        snprintf(frag, sizeof(frag), "%.*s", (int)n, p);
        g_checks++;
        if (!strstr(msg, frag)) {
            g_failed++;
            printf("  [FAIL] %s: message lacks '%s'; it is: %s\n", label, frag, msg);
        }
        p = bar ? bar + 1 : NULL;
    }
}

static const zone_config_t *zone_in_view(const server_config_t *cfg, const char *view, const char *domain) {
    for (const view_config_t *v = cfg->views; v; v = v->next)
        if (strcmp(v->name, view) == 0) return view_find_zone_config(v, domain);
    return NULL;
}

#define AN_KEY "key \"k1\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; };\n"

static void test_also_notify_bind(void) {
    printf("[*] also-notify (BIND 9.20)...\n");
    server_config_t cfg;
    const notify_target_t *t = NULL;
    int n;

    /* options-level: every zone without its own statement (also a zone without zone {}: zone == NULL) */
    if (parse_ok("options { also-notify { 192.0.2.1; 2001:db8::1 port 5301; }; };\n"
                 "zone \"a.test\" { type master; file \"a\"; };", &cfg)) {
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "a.test"), "__default__", &t);
        CHECK(n == 2 && t && t[0].port == 53 && t[1].port == 5301);
        if (n == 2) { CHECK_STR(t[0].ip, "192.0.2.1"); CHECK_STR(t[1].ip, "2001:db8::1"); CHECK(t[0].key == NULL && t[0].list == NULL); }
        CHECK(also_notify_effective(&cfg, NULL, "__default__", &t) == 2);
        CHECK(also_notify_effective(NULL, NULL, NULL, &t) == 0);
        free_server_config_fields(&cfg);
    }
    /* zone replaces options; an empty zone statement switches the inherited list off; a later statement replaces an earlier one */
    if (parse_ok("options { also-notify { 192.0.2.1; }; };\n"
                 "zone \"a.test\" { type master; file \"a\"; also-notify { 192.0.2.2 port 5302; }; };\n"
                 "zone \"b.test\" { type master; file \"b\"; also-notify { }; };\n"
                 "zone \"c.test\" { type master; file \"c\"; also-notify { 192.0.2.7; }; also-notify { 192.0.2.8; 192.0.2.9; }; };\n"
                 "zone \"d.test\" { type master; file \"d\"; };", &cfg)) {
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "a.test"), "__default__", &t);
        CHECK(n == 1 && t && t[0].port == 5302);
        CHECK(also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "b.test"), "__default__", &t) == 0);
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "c.test"), "__default__", &t);
        CHECK(n == 2 && t && strcmp(t[0].ip, "192.0.2.8") == 0);
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "d.test"), "__default__", &t);
        CHECK(n == 1 && t && strcmp(t[0].ip, "192.0.2.1") == 0);
        free_server_config_fields(&cfg);
    }
    /* view-level: overrides options for its zones; a zone still overrides the view; another view keeps options' */
    if (parse_ok("options { also-notify { 192.0.2.1; }; };\n"
                 "view \"in\" { match-clients { 10.0.0.0/8; }; also-notify { 192.0.2.50; 192.0.2.51; };\n"
                 "  zone \"a.test\" { type master; file \"a\"; };\n"
                 "  zone \"b.test\" { type master; file \"b\"; also-notify { 192.0.2.52; }; }; };\n"
                 "view \"out\" { match-clients { any; }; zone \"a.test\" { type master; file \"a\"; }; };", &cfg)) {
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "in", "a.test"), "in", &t);
        CHECK(n == 2 && t && strcmp(t[0].ip, "192.0.2.50") == 0);
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "in", "b.test"), "in", &t);
        CHECK(n == 1 && t && strcmp(t[0].ip, "192.0.2.52") == 0);
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "out", "a.test"), "out", &t);
        CHECK(n == 1 && t && strcmp(t[0].ip, "192.0.2.1") == 0);
        CHECK(also_notify_effective(&cfg, NULL, "in", &t) == 2);   /* a catalog member has no zone { } */
        free_server_config_fields(&cfg);
    }
    /* port before the list is the default port of the elements without their own */
    if (parse_ok("zone \"a.test\" { type master; file \"a\"; also-notify port 5353 { 192.0.2.1; 192.0.2.2 port 5454; 2001:db8::1; }; };", &cfg)) {
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "a.test"), "__default__", &t);
        CHECK(n == 3 && t && t[0].port == 5353 && t[1].port == 5454 && t[2].port == 5353);
        free_server_config_fields(&cfg);
    }
    /* key on an element */
    if (parse_ok(AN_KEY "options { also-notify { 192.0.2.1 key \"k1\"; 192.0.2.2 port 5302 key k1; 192.0.2.3; }; };", &cfg)) {
        n = also_notify_effective(&cfg, NULL, NULL, &t);
        CHECK(n == 3 && t && t[0].key && strcmp(t[0].key, "k1") == 0 && t[1].key && t[1].port == 5302 && t[2].key == NULL);
        free_server_config_fields(&cfg);
    }
    /* list names: remote-servers / primaries / masters, written after their use, with a port and keys, nested; a key on a name
     * is the key of the addresses of the list that have none */
    if (parse_ok(AN_KEY
                 "options { also-notify { sec; 192.0.2.99; sec2 key k1; }; };\n"
                 "zone \"a.test\" { type master; file \"a\"; also-notify port 5300 { inner; }; };\n"
                 "remote-servers sec port 5301 { 192.0.2.10; 192.0.2.11 port 5311 key \"k1\"; };\n"
                 "primaries sec2 { 192.0.2.20; sec3; };\n"
                 "masters sec3 { 2001:db8::30; };\n"
                 "remote-servers inner { 192.0.2.40; };", &cfg)) {
        n = also_notify_effective(&cfg, NULL, NULL, &t);
        CHECK(n == 5);
        if (n == 5) {
            CHECK(strcmp(t[0].ip, "192.0.2.10") == 0 && t[0].port == 5301 && t[0].key == NULL);
            CHECK(strcmp(t[1].ip, "192.0.2.11") == 0 && t[1].port == 5311 && t[1].key && strcmp(t[1].key, "k1") == 0);
            CHECK(strcmp(t[2].ip, "192.0.2.99") == 0 && t[2].port == 53);
            CHECK(strcmp(t[3].ip, "192.0.2.20") == 0 && t[3].port == 53 && t[3].key && strcmp(t[3].key, "k1") == 0);
            CHECK(strcmp(t[4].ip, "2001:db8::30") == 0 && t[4].key && strcmp(t[4].key, "k1") == 0);
            CHECK(t[0].list == NULL && t[0].where == NULL && t[1].where == NULL);
        }
        /* the port of the enclosing statement is the default of the elements of a nested list that has no port (BIND named_config_getipandkeylist(); batch 5) */
        n = also_notify_effective(&cfg, zone_in_view(&cfg, "__default__", "a.test"), "__default__", &t);
        CHECK(n == 1 && t && t[0].port == 5300);
        free_server_config_fields(&cfg);
    }
    /* settings text of a database zone: addresses and ports only */
    {
        char err[200];
        zone_ext_shared_t *sh = db_parse_quiet("also-notify port 5353 { 192.0.2.1; 192.0.2.2 port 5301; };", err, sizeof(err));
        CHECK(sh != NULL);
        if (sh) {
            CHECK(sh->ext.also_notify_set && sh->ext.also_notify_count == 2 && sh->ext.also_notify[0].port == 5353 &&
                  sh->ext.also_notify[1].port == 5301);
            zone_ext_shared_unref(sh);
        }
        expect_db_reject("also-notify { 192.0.2.1 key k; };", "key");
        expect_db_reject("also-notify { somelist; };", "not an IP");
        expect_db_reject("also-notify { 192.0.2.1 tls t; };", "also-notify");
        expect_db_reject("also-notify { 192.0.2.1 };", "also-notify");
    }

    /* errors say what and where (the line of the element / of the token that was wrong) */
    expect_an_error("unknown list name", "options { };\nzone \"z.test\" { type master; file \"z\";\n  also-notify { nolist; }; };",
                    "line 3|zone 'z.test.' also-notify|'nolist'|remote-servers");
    expect_an_error("unknown list in options", "options {\n also-notify { 192.0.2.1;\n  nolist; };\n};", "line 3|options also-notify|'nolist'");
    expect_an_error("unknown list in view", "view \"v\" { match-clients { any; };\n also-notify { nolist; }; };", "line 2|view 'v' also-notify|'nolist'");
    expect_an_error("hostname is not an address", "options { also-notify { ns1.example.test; }; };", "'ns1.example.test'");
    expect_an_error("ip:port is not the port syntax", "zone \"s.test\" { type slave; file \"s\";\n  masters { 192.0.2.254:53; }; };",
                    "line 2|'192.0.2.254:53'|write the port as '<address> port <n>'");
    expect_an_error("undefined key", "options {\n also-notify { 192.0.2.1 key nokey; }; };", "line 2|key 'nokey' is not defined");
    expect_an_error("undefined key on a list", "remote-servers l {\n 192.0.2.1 key nokey; };\noptions { };", "line 2|remote-servers 'l'|key 'nokey'");
    expect_an_error("undefined key on a list name", AN_KEY "remote-servers l { 192.0.2.1; };\noptions { also-notify { l key nokey; }; };",
                    "line 3|key 'nokey' is not defined");
    expect_an_error("missing semicolon", "options { };\nzone \"z.test\" { type master; file \"z\";\n  also-notify { 192.0.2.1 }; };",
                    "line 3|zone 'z.test.' also-notify|expected ';' after '192.0.2.1'");
    expect_an_error("missing semicolon after }", "options {\n also-notify { 192.0.2.1; }\n};", "options also-notify|expected ';' after '}'");
    expect_an_error("no braces", "options { also-notify 192.0.2.1; };", "expected '{'");
    expect_an_error("eof in the list", "options { also-notify { 192.0.2.1;", "missing '}'");
    expect_an_error("bad port", "options { also-notify { 192.0.2.1 port 70000; }; };", "invalid port '70000'");
    expect_an_error("bad default port", "options { also-notify port 0 { 192.0.2.1; }; };", "invalid port '0'");
    expect_an_error("port missing", "options { also-notify { 192.0.2.1 port; }; };", "expected a port number");
    expect_an_error("two ports", "options { also-notify { 192.0.2.1 port 1 port 2; }; };", "two ports");
    expect_an_error("port on a list name", "options { also-notify { l port 5300; }; }; remote-servers l { 192.0.2.1; };", "takes no port");
    expect_an_error("two keys", AN_KEY "options { also-notify { 192.0.2.1 key k1 key k1; }; };", "two keys");
    expect_an_error("key without name", "options { also-notify { 192.0.2.1 key; }; };", "expected a key name");
    expect_an_error("tls", "options { also-notify { 192.0.2.1 tls t; }; };", "'tls' is not supported");
    expect_an_error("source then junk", "options { also-notify source 192.0.2.5 foo { 192.0.2.1; }; };", "expected '{'");
    expect_an_error("source of the wrong family", "options { also-notify source 2001:db8::5 { 192.0.2.1; }; };", "not an IPv4 address");
    expect_an_error("junk after element", "options { also-notify { 192.0.2.1 foo; }; };", "unexpected 'foo'");
    expect_an_error("list includes itself", "options { also-notify { l; }; };\nremote-servers l { 192.0.2.1; l; };", "nested more than");
    expect_an_error("list defined twice", "remote-servers l { 192.0.2.1; };\nprimaries L { 192.0.2.2; };", "line 2|list 'L' is defined twice");
    expect_an_error("list without name", "remote-servers { 192.0.2.1; };", "expected a list name");
    expect_an_error("masters syntax error", "zone \"z.test\" { type slave; masters {\n 192.0.2.1 port x; }; };", "line 2|masters|invalid port 'x'");
    expect_an_error("forwarders syntax error", "zone \"z.test\" { type forward; forwarders { 192.0.2.1 ; 192.0.2.2 192.0.2.3; }; };", "forwarders|expected ';' after '192.0.2.2'");
    {
        /* more than KARIDNS_ALSO_NOTIFY_MAX addresses after expanding: a list that includes a list that includes ... 3 times */
        char big[8192], *w = big;
        w += snprintf(w, 64, "remote-servers a { ");
        for (int i = 0; i < 20; i++) w += snprintf(w, 40, "192.0.2.%d; ", i + 1);
        w += snprintf(w, 16, "};\n");
        w += snprintf(w, 128, "remote-servers b { a; a; a; a; a; a; a; a; a; a; a; a; a; a; };\n");
        w += snprintf(w, 64, "options { also-notify { b; }; };");
        expect_an_error("too many after expansion", big, "more than 256 addresses");
    }
}

/* primaries / masters in a zone (BIND 9.20 ARM "primaries": [ port <integer> ] { ( <remote-servers> | <ipv4> [ port <integer> ] | <ipv6> [ port <integer> ] )
 * [ key <string> ]; ... };) and notify <yes|no|explicit|primary-only|master-only> in options, view and zone. */
static void test_primaries_and_notify_mode(void) {
    printf("[*] primaries / masters lists and notify modes (BIND 9.20)...\n");
    server_config_t cfg;

    /* list names, ports, keys; the zone's tsig-key is the fallback of an address without a key */
    if (parse_ok(AN_KEY "key \"k2\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; };\n"
                 "zone \"s.test\" { type slave; tsig-key \"k2\"; primaries { ps; 2001:db8::5 port 5400; }; };\n"
                 "zone \"t.test\" { type slave; masters port 5353 { 192.0.2.30; ps2; }; };\n"
                 "remote-servers ps port 5300 { 192.0.2.1; 192.0.2.2 port 5301 key k1; };\n"
                 "masters ps2 { 192.0.2.40 port 5360; };", &cfg)) {
        const zone_config_t *z = zone_in_view(&cfg, "__default__", "s.test");
        const zone_ext_t *x = zext(z);
        CHECK(x->masters_count == 3 && x->masters_parsed != NULL);
        if (x->masters_count == 3) {
            CHECK(strcmp(x->masters[0].ip, "192.0.2.1") == 0 && x->masters[0].port == 5300 && x->masters[0].list == NULL);
            CHECK(x->masters[1].port == 5301 && x->masters[1].key && strcmp(x->masters[1].key, "k1") == 0);
            CHECK(strcmp(x->masters[2].ip, "2001:db8::5") == 0 && x->masters[2].port == 5400);
            CHECK_STR(zone_primary_key(x, 0), "k2");   /* no key of its own: the zone's tsig-key */
            CHECK_STR(zone_primary_key(x, 1), "k1");   /* its own key wins */
        }
        x = zext(zone_in_view(&cfg, "__default__", "t.test"));
        CHECK(x->masters_count == 2 && x->masters[0].port == 5353 && x->masters[1].port == 5360 && zone_primary_key(x, 0) == NULL);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"s.test\" { type slave; masters { 192.0.2.1; }; primaries { 192.0.2.2 port 5353; 192.0.2.3; }; };", &cfg)) {
        const zone_ext_t *x = zext(zone_in_view(&cfg, "__default__", "s.test"));
        CHECK(x->masters_count == 2 && strcmp(x->masters[0].ip, "192.0.2.2") == 0 && x->masters[0].port == 5353);   /* a later statement replaces */
        free_server_config_fields(&cfg);
    }
    /* a prefix is accepted in masters (it is only used to decide who may send NOTIFY) and is not read as a list name */
    if (parse_ok("zone \"s.test\" { type slave; masters { 192.0.2.100; 10.0.0.0/8; }; };", &cfg)) {
        const zone_ext_t *x = zext(zone_in_view(&cfg, "__default__", "s.test"));
        CHECK(x->masters_count == 2 && x->masters[1].ip && strcmp(x->masters[1].ip, "10.0.0.0/8") == 0 && x->masters_parsed != NULL);
        free_server_config_fields(&cfg);
    }
    expect_an_error("prefix in also-notify is not an address", "options { also-notify { 10.0.0.0/8; }; };", "'10.0.0.0/8'");
    expect_an_error("unknown primaries list", "zone \"s.test\" { type slave;\n primaries { nolist; }; };", "line 2|zone 's.test.' primaries|'nolist'");
    expect_an_error("primaries key undefined", "zone \"s.test\" { type slave;\n masters { 192.0.2.1 key nokey; }; };", "line 2|key 'nokey' is not defined");
    expect_an_error("primaries tls", "zone \"s.test\" { type slave; primaries { 192.0.2.1 tls t; }; };", "'tls' is not supported");
    expect_an_error("primaries source-v6 with an IPv4 address", "zone \"s.test\" { type slave; primaries source-v6 192.0.2.9 { 192.0.2.1; }; };", "not an IPv6 address");
    expect_an_error("primaries syntax", "zone \"s.test\" { type slave;\n primaries { 192.0.2.1 }; };", "line 2|zone 's.test.' primaries|expected ';'");
    expect_an_error("primaries port on a name", "zone \"s.test\" { type slave; primaries { l port 5; }; }; remote-servers l { 192.0.2.1; };", "takes no port");
    {
        char err[200];
        zone_ext_shared_t *sh = db_parse_quiet("masters port 5353 { 192.0.2.1; 192.0.2.2 port 5301; };", err, sizeof(err));
        CHECK(sh != NULL);
        if (sh) {
            CHECK(sh->ext.masters_count == 2 && sh->ext.masters[0].port == 5353 && sh->ext.masters[1].port == 5301 && sh->ext.masters_parsed != NULL);
            zone_ext_shared_unref(sh);
        }
        expect_db_reject("masters { 192.0.2.1 key k; };", "key");
        expect_db_reject("primaries { somelist; };", "not an IP");
        expect_db_reject("masters { 192.0.2.1 tls t; };", "masters");
    }

    /* notify */
    if (parse_ok("options { notify no; };\n"
                 "view \"v\" { match-clients { any; }; notify explicit;\n"
                 "  zone \"a.test\" { type master; file \"a\"; };\n"
                 "  zone \"b.test\" { type master; file \"b\"; notify master-only; };\n"
                 "  zone \"c.test\" { type master; file \"c\"; notify yes; }; };\n"
                 "view \"w\" { match-clients { 10.0.0.0/8; }; zone \"a.test\" { type master; file \"a\"; }; zone \"d.test\" { type master; file \"d\"; notify primary-only; }; };", &cfg)) {
        CHECK(notify_mode_effective(&cfg, zone_in_view(&cfg, "v", "a.test"), "v") == NOTIFY_MODE_EXPLICIT);
        CHECK(notify_mode_effective(&cfg, zone_in_view(&cfg, "v", "b.test"), "v") == NOTIFY_MODE_PRIMARY_ONLY);
        CHECK(notify_mode_effective(&cfg, zone_in_view(&cfg, "v", "c.test"), "v") == NOTIFY_MODE_YES);
        CHECK(notify_mode_effective(&cfg, zone_in_view(&cfg, "w", "a.test"), "w") == NOTIFY_MODE_NO);   /* options' */
        CHECK(notify_mode_effective(&cfg, zone_in_view(&cfg, "w", "d.test"), "w") == NOTIFY_MODE_PRIMARY_ONLY);
        CHECK(notify_mode_effective(&cfg, NULL, "v") == NOTIFY_MODE_EXPLICIT);                         /* a catalog member */
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"a.test\" { type master; file \"a\"; };", &cfg)) {
        CHECK(notify_mode_effective(&cfg, zone_in_view(&cfg, "__default__", "a.test"), "__default__") == NOTIFY_MODE_YES);   /* the default */
        free_server_config_fields(&cfg);
    }
    CHECK(notify_mode_effective(NULL, NULL, NULL) == NOTIFY_MODE_YES);
    {
        const char *vals[] = { "yes", "true", "1", "YES" };
        for (int i = 0; i < 4; i++) {
            char t[128];
            snprintf(t, sizeof(t), "options { notify %s; };", vals[i]);
            if (parse_ok(t, &cfg)) { CHECK(notify_mode_effective(&cfg, NULL, NULL) == NOTIFY_MODE_YES); free_server_config_fields(&cfg); }
        }
        const char *nos[] = { "no", "false", "0" };
        for (int i = 0; i < 3; i++) {
            char t[128];
            snprintf(t, sizeof(t), "options { notify %s; };", nos[i]);
            if (parse_ok(t, &cfg)) { CHECK(notify_mode_effective(&cfg, NULL, NULL) == NOTIFY_MODE_NO); free_server_config_fields(&cfg); }
        }
    }
    expect_an_error("notify bad value", "options {\n notify maybe; };", "line 2|options notify|invalid value 'maybe'");
    expect_an_error("notify in zone bad value", "zone \"a.test\" { type master; notify sometimes; };", "zone 'a.test.' notify|invalid value");
    expect_an_error("notify in view bad value", "view \"v\" { notify x; };", "view 'v' notify");
    expect_an_error("notify missing semicolon", "options { notify no };", "options notify|expected ';'");
    expect_an_error("notify missing value", "options { notify; };", "expected yes, no, explicit or primary-only");
    expect_db_reject("notify no;", "notify");
}

/* Strict options { } and key { } (decided 2026-10-28): an unknown statement is a configuration error with file:line, a BIND
 * option KariDNS does not implement is skipped with a warning, and every statement KariDNS implements is accepted without
 * either message. */
static void test_strict_options_and_key(void) {
    printf("[TEST] strict options { } and key { }...\n");
    server_config_t cfg;
    char msg[2048], txt[1024];

    /* every implemented options statement: parses, and neither warns nor errors about being unknown */
    static const struct { const char *name, *sample; } impl[] = {
        {"port", "port 5353;"}, {"directory", "directory \"/var/db\";"}, {"user", "user \"nobody\";"}, {"group", "group \"nobody\";"},
        {"pid-file", "pid-file \"/var/run/x.pid\";"}, {"bind-address", "bind-address { 192.0.2.1; };"},
        {"rate-limit", "rate-limit { responses-per-second 5; };"}, {"ecs-enable", "ecs-enable yes;"},
        {"ecs-trusted-resolvers", "ecs-trusted-resolvers { 192.0.2.53; };"},
        {"ecs-tags", "ecs-tags { tag \"a\" { 192.0.2.0/24; }; };"},
        {"location-tags", "location-tags { tag \"a\" { 192.0.2.0/24; }; };"},
        {"send-extended-errors", "send-extended-errors yes;"}, {"serve-stale", "serve-stale yes;"},
        {"rfc10029-mqtype", "rfc10029-mqtype yes;"}, {"tcp-connection-reuse", "tcp-connection-reuse yes;"},
        {"tcp-idle-timeout", "tcp-idle-timeout 5000ms;"}, {"tcp-initial-timeout", "tcp-initial-timeout 5000ms;"},
        {"cookie-secret", "cookie-secret \"00112233445566778899aabbccddeeff\";"},
        {"cookie-algorithm", "cookie-algorithm siphash24;"}, {"nsid", "nsid \"ns1.example\";"},
        {"minimal-responses", "minimal-responses yes;"}, {"minimal-any", "minimal-any yes;"},
        {"additional-from-auth", "additional-from-auth yes;"}, {"query-log-max-qps", "query-log-max-qps 10;"},
        {"query-log-buffer-size", "query-log-buffer-size 4096;"}, {"allow-program-zones", "allow-program-zones yes;"},
        {"max-mqtypes", "max-mqtypes 3;"}, {"querylog", "querylog yes;"}, {"minimal-any-ttl", "minimal-any-ttl 300;"},
        {"wire-cache-max-records", "wire-cache-max-records 100;"}, {"alias-resolver", "alias-resolver { 192.0.2.53; };"},
        {"ixfr-history", "ixfr-history 10;"}, {"max-zone-records", "max-zone-records 100000;"},
        {"max-zone-bytes", "max-zone-bytes 1m;"}, {"tcp-mss", "tcp-mss 1220;"}, {"tcp-window", "tcp-window 65536;"},
        {"udp-bufsize", "udp-bufsize 1232;"}, {"udp-recvbuf-size", "udp-recvbuf-size 1m;"},
        {"response-cache-size", "response-cache-size 1m;"}, {"udp-sndbuf-size", "udp-sndbuf-size 1m;"},
        {"dnstap", "dnstap { socket \"/x.sock\"; };"},
        {"database", "database { driver sqlite3; database-file \"/x.db\"; };"}, {"notify", "notify yes;"},
        {"also-notify", "also-notify { 192.0.2.1; };"}, {"notify-retries", "notify-retries 3;"},
        {"allow-query", "allow-query { any; };"}, {"allow-query-on", "allow-query-on { any; };"},
        {"allow-transfer", "allow-transfer { none; };"}, {"allow-update", "allow-update { none; };"},
        {"allow-notify", "allow-notify { 192.0.2.1; };"},
        {"listen-on", "listen-on port 5353 { 127.0.0.1; };"}, {"listen-on-v6", "listen-on-v6 { none; };"},
        {"blackhole", "blackhole { 192.0.2.0/24; };"}, {"notify-retry-interval", "notify-retry-interval 5;"}, {"notify-retry-backoff", "notify-retry-backoff fixed;"},
    };
    for (size_t i = 0; i < sizeof(impl) / sizeof(impl[0]); i++) {
        snprintf(txt, sizeof(txt), "options { %s };", impl[i].sample);
        int rc = parse_capture(txt, &cfg, msg, sizeof(msg));
        g_checks++;
        if (rc != 0) {
            g_failed++;
            printf("  [FAIL] implemented option '%s' rejected: %s\n         %s\n", impl[i].name, txt, msg);
            continue;
        }
        free_server_config_fields(&cfg);
        g_checks++;
        if (strstr(msg, "does not implement") || strstr(msg, "unknown option")) {
            g_failed++;
            printf("  [FAIL] implemented option '%s' reported as unknown/unimplemented: %s\n", impl[i].name, msg);
        }
    }

    /* a BIND option KariDNS does not implement: warning, skipped, the rest of options { } still applies */
    static const char *const bind_only[] = {
        "recursion no;",
        "min-transfer-rate-in 10240 5;" /* BIND 9.20 only; not implemented */, "zero-no-soa-ttl yes;", "dnssec-validation auto;", "forwarders { 192.0.2.1; };",
        "max-cache-size 100m;", "allow-new-zones yes;", "dnssec-enable yes;" /* BIND 9.16 and older */,
        "allow-proxy { any; };" /* BIND 9.20 only */, "use-alt-transfer-source no;" /* BIND 9.18 only */,
        "reuseport yes;", "tkey-dhkey \"k\" 1;",
    };
    for (size_t i = 0; i < sizeof(bind_only) / sizeof(bind_only[0]); i++) {
        snprintf(txt, sizeof(txt), "options {\n %s\n port 5300;\n};", bind_only[i]);
        int rc = parse_capture(txt, &cfg, msg, sizeof(msg));
        g_checks += 3;
        if (rc != 0) { g_failed++; printf("  [FAIL] BIND option rejected: %s\n         %s\n", bind_only[i], msg); continue; }
        if (cfg.port != 5300) { g_failed++; printf("  [FAIL] statement after '%s' lost\n", bind_only[i]); }
        free_server_config_fields(&cfg);
        /* the location is "line 2" for a configuration given as a string */
        if (!strstr(msg, "[WARNING]") || !strstr(msg, "is a BIND option that KariDNS does not implement") || !strstr(msg, "line 2")) {
            g_failed++;
            printf("  [FAIL] no warning with a line for '%s': %s\n", bind_only[i], msg);
        }
    }

    /* anything else is an error with the line */
    expect_an_error("misspelt bind-address", "options {\n port 53;\n bind-adress { 192.0.2.1; };\n};",
                    "line 3|options|unknown option 'bind-adress'");
    expect_an_error("misspelt user", "options { usr \"nobody\"; };", "unknown option 'usr'");
    expect_an_error("misspelt pid-file", "options { pidfile \"/x\"; };", "unknown option 'pidfile'");
    expect_an_error("misspelt allow-transfer is not a BIND option either", "options { allow-tranfer { any; }; };",
                    "unknown option 'allow-tranfer'");
    expect_an_error("unknown block", "options { frobnicate { a; b; }; };", "unknown option 'frobnicate'");
    expect_an_error("karidns option in the wrong block", "options { tcp-idle-timeouts 5; };", "unknown option");
    expect_an_error("statement after the typo is not reached", "options { qps-scale 4; port 5300; };", "unknown option 'qps-scale'");

    /* key { }: algorithm and secret; BIND documents nothing else, so any other statement is an error */
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; secret \"%s\"; };", SECRET_OK);
    if (parse_ok(txt, &cfg)) { CHECK(cfg.keys && cfg.keys->secret_decoded_len == 32); free_server_config_fields(&cfg); }
    snprintf(txt, sizeof(txt), "key \"k\" {\n algorithm hmac-sha256;\n scret \"%s\";\n};", SECRET_OK);
    expect_an_error("misspelt secret", txt, "line 3|key 'k'|unknown option 'scret'");
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; secret \"%s\"; comment { x; }; };", SECRET_OK);
    expect_an_error("unknown block in key", txt, "unknown option 'comment'");
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; algo hmac-sha256; secret \"%s\"; };", SECRET_OK);
    expect_an_error("misspelt algorithm", txt, "unknown option 'algo'");
    /* a key that cannot sign must not exist */
    expect_an_error("key without secret", "key \"k\" { algorithm hmac-sha256; };", "key 'k'|'secret' is missing");
    snprintf(txt, sizeof(txt), "key \"k\" { secret \"%s\"; };", SECRET_OK);
    expect_an_error("key without algorithm", txt, "key 'k'|'algorithm' is missing");
    expect_an_error("empty key", "key \"k\" { };", "is missing");
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; algorithm hmac-sha512; secret \"%s\"; };", SECRET_OK);
    expect_an_error("algorithm twice", txt, "'algorithm' is given twice");
    snprintf(txt, sizeof(txt), "key \"k\" { algorithm hmac-sha256; secret \"%s\"; secret \"%s\"; };", SECRET_OK, SECRET_OK);
    expect_an_error("secret twice", txt, "'secret' is given twice");

    /* logging { } is strict since batch 6; unknown top-level statements still skip unknowns (out of scope) */
    expect_an_error("unknown statement in logging", "logging {\n frobnicate yes;\n};", "line 2|logging|unknown statement 'frobnicate'");
    if (parse_ok("frobnicate-block { a; };", &cfg)) free_server_config_fields(&cfg);
}

/* ---- BIND compatibility, batch 1: directory, class after zone / view names, zone types that are not loaded, port errors ----
 * Expectations from the BIND 9.20 ARM: `directory` "sets the working directory of the server" and "all relative paths use this directory as
 * a base" (named.conf sample, 3.1.1); `zone <string> [ <class> ] {`, `view <string> [ <class> ] {`; zone types "primary (or master), secondary
 * (or slave), mirror, hint, stub, static-stub, forward, or redirect". */
#define N_ELEM(a) (sizeof(a) / sizeof((a)[0]))
static void write_file_t(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f) { printf("  [FAIL] cannot write %s\n", path); g_failed++; return; }
    fputs(text, f);
    fclose(f);
}

static bool parse_file_capture(const char *path, server_config_t *cfg, char *msg, size_t msglen) {
    char *text = read_entire_file(path, NULL, NULL);
    if (!text) { msg[0] = '\0'; return false; }
    char errpath[] = "/tmp/bcp_err_XXXXXX";
    int tmp = mkstemp(errpath);
    fflush(stderr);
    int saved = dup(2);
    if (tmp >= 0) dup2(tmp, 2);
    int rc = parse_named_conf_ext(text, path, cfg);
    fflush(stderr);
    if (saved >= 0) { dup2(saved, 2); close(saved); }
    msg[0] = '\0';
    if (tmp >= 0) {
        ssize_t n = pread(tmp, msg, msglen - 1, 0);
        msg[n > 0 ? n : 0] = '\0';
        close(tmp);
        unlink(errpath);
    }
    free(text);
    return rc == 0;
}

static void test_bind_compat_paths(void) {
    printf("[TEST] BIND compatibility batch 1: directory, class, skipped zone types, port...\n");
    server_config_t cfg;
    char msg[2048];

    /* directory: every relative path of the configuration is relative to it (also when the statement comes last) */
    if (parse_ok("options { pid-file \"run/k.pid\"; directory \"/var/named\"; };\n"
                 "logging { channel q { file \"log/q.log\"; }; channel a { file \"/abs/a.log\"; }; };\n"
                 "control-channel { socket \"ctl.sock\"; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; algorithm hmac-sha256; };\n"
                 "zone \"example\" { type primary; file \"db.example\"; };\n"
                 "zone \"abs.example\" { type primary; file \"/srv/abs.db\"; };\n"
                 "zone \"sub.example\" { type primary; file \"zones/sub.db\"; };\n", &cfg)) {
        CHECK_STR(cfg.directory, "/var/named");
        CHECK_STR(cfg.pid_file, "/var/named/run/k.pid");
        CHECK(!cfg.directory_changed);
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z != NULL);
        if (z) CHECK_STR(z->file, "/var/named/db.example");
        const view_config_t *v = cfg.views;
        CHECK(v && v->zones && v->zones->next && v->zones->next->next);
        if (v && v->zones && v->zones->next && v->zones->next->next) {
            CHECK_STR(v->zones->next->file, "/srv/abs.db");
            CHECK_STR(v->zones->next->next->file, "/var/named/zones/sub.db");
        }
        const log_channel_t *qc = find_channel(&cfg, "q");
        CHECK(qc && qc->file_path && strcmp(qc->file_path, "/var/named/log/q.log") == 0);
        const log_channel_t *ac = find_channel(&cfg, "a");
        CHECK(ac && ac->file_path && strcmp(ac->file_path, "/abs/a.log") == 0);
        CHECK_STR(cfg.control.socket_path, "ctl.sock");   /* sockets are not prefixed: sun_path is short; the server chdir()s to directory */
        free_server_config_fields(&cfg);
    }
    /* "none" for pid-file is not a path */
    if (parse_ok("options { directory \"/var/named\"; pid-file \"none\"; };", &cfg)) {
        CHECK_STR(cfg.pid_file, "none");
        free_server_config_fields(&cfg);
    }
    /* no directory: paths are untouched (relative to the directory the server is started in) */
    if (parse_ok("options { pid-file \"run/k.pid\"; };\nzone \"example\" { type primary; file \"db.example\"; };", &cfg)) {
        CHECK(cfg.directory == NULL);
        CHECK_STR(cfg.pid_file, "run/k.pid");
        const zone_config_t *z = first_zone(&cfg);
        if (z) CHECK_STR(z->file, "db.example");
        free_server_config_fields(&cfg);
    }
    /* a relative directory is kept as written (relative to the startup directory) */
    if (parse_ok("options { directory \"named\"; };\nzone \"example\" { type primary; file \"db.example\"; };", &cfg)) {
        CHECK_STR(cfg.directory, "named");
        const zone_config_t *z = first_zone(&cfg);
        if (z) CHECK_STR(z->file, "named/db.example");
        free_server_config_fields(&cfg);
    }
    expect_an_error("empty directory", "options { directory \"\"; };", "line 1|options|directory");

    /* the directory of the running server (config_pin_directory) wins on a reload; another one is reported */
    config_pin_directory("/pinned");
    if (parse_ok("options { directory \"/other\"; };\nzone \"example\" { type primary; file \"db.example\"; };", &cfg)) {
        CHECK_STR(cfg.directory, "/pinned");
        CHECK(cfg.directory_changed);
        const zone_config_t *z = first_zone(&cfg);
        if (z) CHECK_STR(z->file, "/pinned/db.example");
        free_server_config_fields(&cfg);
    }
    if (parse_ok("options { directory \"/pinned\"; };\nzone \"example\" { type primary; file \"db.example\"; };", &cfg)) {
        CHECK_STR(cfg.directory, "/pinned");
        CHECK(!cfg.directory_changed);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"example\" { type primary; file \"db.example\"; };", &cfg)) {     /* the file no longer has it */
        CHECK_STR(cfg.directory, "/pinned");
        CHECK(cfg.directory_changed);
        free_server_config_fields(&cfg);
    }
    config_pin_directory(NULL);                                                          /* started without a directory */
    if (parse_ok("options { directory \"/new\"; };\nzone \"example\" { type primary; file \"db.example\"; };", &cfg)) {
        CHECK(cfg.directory == NULL);
        CHECK(cfg.directory_changed);
        const zone_config_t *z = first_zone(&cfg);
        if (z) CHECK_STR(z->file, "db.example");
        free_server_config_fields(&cfg);
    }
    config_unpin_directory();

    /* include: relative to directory when it is set, else to the including file */
    char root[] = "/tmp/bcp_dir_XXXXXX";
    if (!mkdtemp(root)) { printf("  [FAIL] mkdtemp\n"); g_failed++; return; }
    char p[PATH_MAX], q[PATH_MAX];
    snprintf(p, sizeof(p), "%s/etc", root);   mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/base", root);  mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/other", root); mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/base/keys.conf", root);
    write_file_t(p, "key \"kb\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; };\n");
    snprintf(p, sizeof(p), "%s/etc/keys.conf", root);
    write_file_t(p, "key \"ke\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; };\n");
    snprintf(p, sizeof(p), "%s/etc/main.conf", root);
    snprintf(q, sizeof(q), "options { directory \"%s/base\"; };\ninclude \"keys.conf\";\n", root);
    write_file_t(p, q);
    if (parse_file_capture(p, &cfg, msg, sizeof(msg))) {
        CHECK(cfg.keys && strcmp(cfg.keys->name, "kb") == 0);      /* base/keys.conf, not etc/keys.conf */
        free_server_config_fields(&cfg);
    } else { g_failed++; printf("  [FAIL] include relative to directory: %s\n", msg); }
    /* the same file with directory after the include (BIND applies it to all of them) */
    snprintf(q, sizeof(q), "include \"keys.conf\";\noptions { directory \"%s/base\"; };\n", root);
    write_file_t(p, q);
    if (parse_file_capture(p, &cfg, msg, sizeof(msg))) {
        CHECK(cfg.keys && strcmp(cfg.keys->name, "kb") == 0);
        free_server_config_fields(&cfg);
    } else { g_failed++; printf("  [FAIL] include before directory: %s\n", msg); }
    /* no directory: relative to the including file */
    write_file_t(p, "include \"keys.conf\";\n");
    if (parse_file_capture(p, &cfg, msg, sizeof(msg))) {
        CHECK(cfg.keys && strcmp(cfg.keys->name, "ke") == 0);
        free_server_config_fields(&cfg);
    } else { g_failed++; printf("  [FAIL] include without directory: %s\n", msg); }
    /* an absolute include is untouched by directory */
    snprintf(q, sizeof(q), "options { directory \"%s/other\"; };\ninclude \"%s/etc/keys.conf\";\n", root, root);
    write_file_t(p, q);
    if (parse_file_capture(p, &cfg, msg, sizeof(msg))) {
        CHECK(cfg.keys && strcmp(cfg.keys->name, "ke") == 0);
        free_server_config_fields(&cfg);
    } else { g_failed++; printf("  [FAIL] absolute include: %s\n", msg); }
    /* directory written in an included file after a relative include was read: cannot be applied to it, so it is refused */
    snprintf(q, sizeof(q), "%s/etc/dir.conf", root);
    snprintf(p, sizeof(p), "%s/other", root);
    {
        char body[PATH_MAX + 64];
        snprintf(body, sizeof(body), "options { directory \"%s\"; };\n", p);
        write_file_t(q, body);
    }
    snprintf(p, sizeof(p), "%s/etc/main.conf", root);
    write_file_t(p, "include \"keys.conf\";\ninclude \"dir.conf\";\n");
    CHECK(!parse_file_capture(p, &cfg, msg, sizeof(msg)));
    CHECK(strstr(msg, "main configuration file") != NULL);
    /* ... but directory only in an included file, with no relative include before it, is fine */
    write_file_t(p, "include \"dir.conf\";\n");
    if (parse_file_capture(p, &cfg, msg, sizeof(msg))) {
        char want[PATH_MAX];
        snprintf(want, sizeof(want), "%s/other", root);
        CHECK_STR(cfg.directory, want);
        free_server_config_fields(&cfg);
    } else { g_failed++; printf("  [FAIL] directory in an included file: %s\n", msg); }
    {
        char cmd[PATH_MAX + 16];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
        if (system(cmd) != 0) printf("  [WARN] cleanup of %s failed\n", root);
    }

    /* a class after the zone / view name: IN (any case) is accepted and ignored */
    static const char *const in_ok[] = {
        "zone \"example\" IN { type primary; file \"a.db\"; };",
        "zone \"example\" in { type primary; file \"a.db\"; };",
        "zone \"example\" In { type primary; file \"a.db\"; };",
        "view \"v\" IN { match-clients { any; }; zone \"example\" IN { type primary; file \"a.db\"; }; };",
        "view \"v\" in { zone \"example\" { type primary; file \"a.db\"; }; };",
    };
    for (size_t i = 0; i < N_ELEM(in_ok); i++) {
        if (parse_ok(in_ok[i], &cfg)) {
            const zone_config_t *z = first_zone(&cfg);
            CHECK(z != NULL);
            if (z) CHECK_STR(z->file, "a.db");
            free_server_config_fields(&cfg);
        }
    }
    /* any other class is an error with file:line and the name of the zone / view */
    expect_an_error("zone CH", "options { };\nzone \"example\" CH { type primary; file \"a.db\"; };", "line 2|zone 'example.'|class 'CH' is not supported (only IN)");
    expect_an_error("zone hs", "zone \"example\" hs { type primary; };", "line 1|class 'hs'");
    expect_an_error("zone CHAOS", "zone \"example\" CHAOS { type primary; };", "class 'CHAOS'");
    expect_an_error("zone CLASS3", "zone \"example\" CLASS3 { type primary; };", "class 'CLASS3'");
    expect_an_error("view CH", "\n\nview \"v\" CH { match-clients { any; }; };", "line 3|view 'v'|class 'CH' is not supported");
    expect_an_error("zone junk", "zone \"example\" frobnicate { type primary; };", "line 1|zone 'example.'|expected '{'");
    expect_an_error("zone no brace", "zone \"example\" IN type primary;", "line 1|expected '{'");
    expect_an_error("quoted class", "zone \"example\" \"IN\" { type primary; };", "expected '{'");

    /* zone types of resolvers: the zone is not loaded and the configuration is accepted (a stock BIND named.conf) */
    static const char *const skipped[] = { "hint", "stub", "static-stub", "mirror", "redirect", "delegation-only", "HINT", "Stub" };
    for (size_t i = 0; i < N_ELEM(skipped); i++) {
        char txt[512];
        snprintf(txt, sizeof(txt),
                 "zone \".\" IN { type %s; file \"named.root\"; masters { 192.0.2.1; }; forwarders { 192.0.2.2 port 5353; }; "
                 "server-addresses { 2001:db8::1; }; };\nzone \"example\" { type primary; file \"a.db\"; };", skipped[i]);
        int rc = parse_capture(txt, &cfg, msg, sizeof(msg));
        CHECK_MSG(rc == 0, "type %s: %s", skipped[i], msg);
        if (rc == 0) {
            CHECK(strstr(msg, "line 1") != NULL && strstr(msg, "is not loaded") != NULL);
            CHECK(view_find_zone_config(cfg.views, ".") == NULL);
            const zone_config_t *z = first_zone(&cfg);
            CHECK(z != NULL && strcmp(z->domain, "example.") == 0);
            CHECK(cfg.views && cfg.views->zones && !cfg.views->zones->next);
            free_server_config_fields(&cfg);
        }
    }
    /* only skipped zones: an empty configuration, still valid; a skipped top-level zone does not forbid views */
    if (parse_ok("zone \".\" { type hint; file \"named.root\"; };", &cfg)) {
        CHECK(cfg.views && !cfg.views->zones);
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \".\" { type hint; file \"named.root\"; };\nview \"v\" { match-clients { any; }; zone \"x\" { type primary; file \"x.db\"; }; };", &cfg)) {
        CHECK(cfg.views && strcmp(cfg.views->name, "v") == 0 && cfg.views->zones);
        free_server_config_fields(&cfg);
    }
    /* inside a view */
    if (parse_ok("view \"v\" { match-clients { any; }; zone \".\" { type hint; file \"r\"; }; zone \"x\" { type primary; file \"x.db\"; }; };", &cfg)) {
        CHECK(view_find_zone_config(cfg.views, ".") == NULL && view_find_zone_config(cfg.views, "x") != NULL);
        free_server_config_fields(&cfg);
    }
    /* the rest of a skipped block is skipped as a whole, braces and all; an unterminated one is an error */
    expect_an_error("unterminated skipped zone", "zone \".\" { type hint; file \"r\"; ", "");
    expect_reject("skipped zone without ';'", "zone \".\" { type hint; } zone \"x\" { type primary; };");
    /* forward keeps its KariDNS meaning; in-view is a clear error (not an empty zone) */
    if (parse_ok("zone \"f.example\" { type forward; forwarders { 192.0.2.53; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->type && strcmp(z->type, "forward") == 0);
        free_server_config_fields(&cfg);
    }
    expect_an_error("in-view", "view \"a\" { zone \"x\" { type primary; file \"x.db\"; }; };\nview \"b\" { zone \"x\" { in-view \"a\"; }; };",
                    "zone 'x.'|in-view|not supported");
    expect_an_error("unknown type", "zone \"x\" { type frobnicate; };", "Unknown zone type 'frobnicate'");

    /* options { port }: only 1..65535 digits */
    static const char *const bad_ports[] = { "abc", "0", "65536", "53x", "-1", "99999999999", "0x35", "" };
    for (size_t i = 0; i < N_ELEM(bad_ports); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "\noptions { port \"%s\"; };", bad_ports[i]);
        expect_an_error(bad_ports[i], txt, "line 2|options|port|1-65535");
    }
    if (parse_ok("options { port 65535; };", &cfg)) { CHECK(cfg.port == 65535); free_server_config_fields(&cfg); }
    if (parse_ok("options { port 1; };", &cfg)) { CHECK(cfg.port == 1); free_server_config_fields(&cfg); }
    /* the port of the other statements that take one */
    expect_an_error("forwarders port", "zone \"f\" { type forward; forwarders { 192.0.2.1 port 0; }; };", "port|1-65535");
    expect_an_error("forwarders port text", "zone \"f\" { type forward; forwarders { 192.0.2.1 port x; }; };", "port|1-65535");
    expect_an_error("also-notify port", "options { also-notify { 192.0.2.1 port 70000; }; };", "port|1-65535");
    expect_an_error("masters list port", "primaries p port 0 { 192.0.2.1; };", "port|1-65535");
    expect_an_error("masters port", "zone \"s\" { type secondary; primaries { 192.0.2.1 port 65536; }; };", "port|1-65535");
}

/* ---- BIND compatibility, batch 6: logging { }, querylog, controls { }, statistics-channels ----
 * Expectations from the BIND 9.20.4 source: lib/isccfg/namedconf.c (channel_clauses, logfile_fields / parse_logfile(), parse_logseverity() with
 * loglevel_enums, printtime_enums, logsuffix_enums, logversions_enums, size_enums, cfg_type_controls / inetcontrol_fields /
 * controls_sockaddr_flags), lib/isccfg/check.c (check_logging(): one destination, "undefined category", "undefined channel"; check_controls():
 * "unknown key", "already defined", "unix control ... not supported"), bin/named/logconf.c (channel_fromconf(): defaults, facility, print flags,
 * debug N as the level, versions / size / suffix), lib/isc/syslog.c (the facility names). */

/* parse; `want` fragments (separated by '|') must all be in the messages of a parse that worked */
static bool ok_with(const char *label, const char *txt, const char *want, server_config_t *cfg) {
    char msg[4096];
    int rc = parse_capture(txt, cfg, msg, sizeof(msg));
    g_checks++;
    if (rc != 0) {
        g_failed++;
        printf("  [FAIL] %s: rejected: %s\n         %s\n", label, txt, msg);
        return false;
    }
    char frag[256];
    const char *p = want;
    while (p && *p) {
        const char *bar = strchr(p, '|');
        size_t n = bar ? (size_t)(bar - p) : strlen(p);
        snprintf(frag, sizeof(frag), "%.*s", (int)n, p);
        g_checks++;
        if (!strstr(msg, frag)) {
            g_failed++;
            printf("  [FAIL] %s: message lacks '%s'; it is: %s\n", label, frag, msg);
        }
        p = bar ? bar + 1 : NULL;
    }
    return true;
}

static void expect_silent(const char *label, const char *txt, server_config_t *cfg) {
    char msg[4096];
    int rc = parse_capture(txt, cfg, msg, sizeof(msg));
    g_checks += 2;
    if (rc != 0) { g_failed++; printf("  [FAIL] %s: rejected: %s\n", label, msg); return; }
    if (msg[0]) { g_failed++; printf("  [FAIL] %s: not silent: %s\n", label, msg); }
}

static void test_bind_logging(void) {
    printf("[*] logging { } (BIND 9.20), querylog, controls { }...\n");
    server_config_t cfg;

    /* a configuration that uses every clause, in the shapes the ARM shows */
    if (ok_with("full logging statement",
                "logging {\n"
                "  channel simple_log { file \"/var/log/named/some_file\" versions 3 size 20m; severity warning; print-time yes; print-severity yes; print-category yes; };\n"
                "  channel audit_log { file \"/var/log/named/audit.log\" size 5m suffix timestamp versions unlimited; severity info; print-time iso8601-utc; };\n"
                "  channel syslog_ch { syslog LOCAL5; severity notice; };\n"
                "  channel err { stderr; severity debug 3; print-time local; buffered no; };\n"
                "  channel off { null; };\n"
                "  channel dbg { stderr; severity debug; };\n"
                "  channel dyn { stderr; severity dynamic; print-time iso8601; };\n"
                "  channel crit { syslog; severity critical; };\n"
                "  category default { simple_log; default_syslog; };\n"
                "  category xfer-in { audit_log; };\n"
                "  category queries { err; off; };\n"
                "  category security { syslog_ch; default_stderr; default_debug; null; };\n"
                "};\n", "", &cfg)) {
        const log_channel_t *s = find_channel(&cfg, "simple_log"), *a = find_channel(&cfg, "audit_log");
        const log_channel_t *y = find_channel(&cfg, "syslog_ch"), *e = find_channel(&cfg, "err"), *o = find_channel(&cfg, "off");
        const log_channel_t *d = find_channel(&cfg, "dbg"), *dy = find_channel(&cfg, "dyn"), *cr = find_channel(&cfg, "crit");
        CHECK(s && s->dest == LOGDEST_FILE && s->versions == 3 && s->size_limit == 20ULL * 1024 * 1024 && !s->suffix_timestamp);
        CHECK(s && s->level == LOG_LVL_WARNING && s->time_fmt == LOGTIME_LOCAL && s->print_severity && s->print_category);
        CHECK(a && a->versions == LOG_VERSIONS_UNLIMITED && a->suffix_timestamp && a->time_fmt == LOGTIME_ISO8601_UTC);
        CHECK(a && a->level == LOG_LVL_INFO && !a->print_category && !a->print_severity);
        CHECK(y && y->dest == LOGDEST_SYSLOG && y->syslog_facility == LOG_LOCAL5 && y->level == LOG_LVL_NOTICE && y->time_fmt == LOGTIME_NONE);
        CHECK(e && e->dest == LOGDEST_STDERR && e->level == 3 && e->time_fmt == LOGTIME_LOCAL && !e->buffered);
        CHECK(o && o->dest == LOGDEST_NULL && o->level == LOG_LVL_INFO);            /* BIND: info when severity is not written */
        CHECK(d && d->level == 1);                                                  /* `debug` alone is debug 1 */
        CHECK(dy && dy->level == LOG_LVL_DYNAMIC && dy->time_fmt == LOGTIME_ISO8601);
        CHECK(cr && cr->dest == LOGDEST_SYSLOG && cr->syslog_facility == LOG_DAEMON && cr->level == LOG_LVL_CRITICAL);
        CHECK(cfg.logging.cat[LOGC_DEFAULT].n == 2 && strcmp(cfg.logging.cat[LOGC_DEFAULT].name[1], "default_syslog") == 0);
        CHECK(cfg.logging.cat[LOGC_XFER_IN].n == 1 && cfg.logging.cat[LOGC_SECURITY].n == 4);
        CHECK(cfg.logging.queries_enabled && !cfg.logging.responses_enabled);
        free_server_config_fields(&cfg);
    }
    /* the defaults of a channel: a file with nothing else (ROLLNEVER, no size), info, no prefixes */
    if (ok_with("channel defaults", "logging { channel c { file \"/tmp/c.log\"; }; };", "", &cfg)) {
        const log_channel_t *c = find_channel(&cfg, "c");
        CHECK(c && c->versions == LOG_VERSIONS_UNSET && c->size_limit == 0 && !c->suffix_timestamp && c->level == LOG_LVL_INFO);
        CHECK(c && c->time_fmt == LOGTIME_NONE && !c->print_category && !c->print_severity && !c->buffered);
        free_server_config_fields(&cfg);
    }

    /* every severity word, in any case; debug with and without a level; debug 0 is dynamic */
    static const struct { const char *text; int level; } sev[] = {
        { "critical", LOG_LVL_CRITICAL }, { "ERROR", LOG_LVL_ERROR }, { "Warning", LOG_LVL_WARNING }, { "notice", LOG_LVL_NOTICE },
        { "info", LOG_LVL_INFO }, { "dynamic", LOG_LVL_DYNAMIC }, { "debug", 1 }, { "debug 1", 1 }, { "debug 99", 99 }, { "debug 0", 0 },
    };
    for (size_t i = 0; i < sizeof(sev) / sizeof(sev[0]); i++) {
        char txt[200];
        snprintf(txt, sizeof(txt), "logging { channel c { null; severity %s; }; };", sev[i].text);
        if (ok_with(sev[i].text, txt, "", &cfg)) {
            const log_channel_t *c = find_channel(&cfg, "c");
            CHECK_MSG(c && c->level == sev[i].level, "severity %s", sev[i].text);
            free_server_config_fields(&cfg);
        }
    }
    expect_an_error("severity word", "logging { channel c { null; severity loud; }; };", "line 1|severity: invalid severity 'loud'");
    expect_an_error("debug level", "logging { channel c { null; severity debug x; }; };", "invalid debug level");
    expect_an_error("negative debug level", "logging { channel c { null; severity debug -1; }; };", "invalid debug level");

    /* print-time: booleans in every spelling, local, iso8601, iso8601-utc */
    static const struct { const char *text; log_time_t fmt; } pt[] = {
        { "yes", LOGTIME_LOCAL }, { "true", LOGTIME_LOCAL }, { "1", LOGTIME_LOCAL }, { "no", LOGTIME_NONE }, { "false", LOGTIME_NONE },
        { "0", LOGTIME_NONE }, { "local", LOGTIME_LOCAL }, { "iso8601", LOGTIME_ISO8601 }, { "iso8601-utc", LOGTIME_ISO8601_UTC },
        { "ISO8601-UTC", LOGTIME_ISO8601_UTC },
    };
    for (size_t i = 0; i < sizeof(pt) / sizeof(pt[0]); i++) {
        char txt[200];
        snprintf(txt, sizeof(txt), "logging { channel c { null; print-time %s; }; };", pt[i].text);
        if (ok_with(pt[i].text, txt, "", &cfg)) {
            const log_channel_t *c = find_channel(&cfg, "c");
            CHECK_MSG(c && c->time_fmt == pt[i].fmt, "print-time %s", pt[i].text);
            free_server_config_fields(&cfg);
        }
    }
    expect_an_error("print-time value", "logging {\n channel c {\n  null;\n  print-time utc;\n };\n};", "line 4|print-time: invalid value 'utc'");

    /* syslog facilities: all names of lib/isc/syslog.c, case-insensitive; an unknown one is BIND's daemon, with a warning here */
    static const struct { const char *name; int fac; } facs[] = {
        { "kern", LOG_KERN }, { "user", LOG_USER }, { "mail", LOG_MAIL }, { "daemon", LOG_DAEMON }, { "auth", LOG_AUTH }, { "syslog", LOG_SYSLOG },
        { "lpr", LOG_LPR }, { "news", LOG_NEWS }, { "uucp", LOG_UUCP }, { "cron", LOG_CRON }, { "authpriv", LOG_AUTHPRIV }, { "ftp", LOG_FTP },
        { "local0", LOG_LOCAL0 }, { "local1", LOG_LOCAL1 }, { "local2", LOG_LOCAL2 }, { "local3", LOG_LOCAL3 }, { "local4", LOG_LOCAL4 },
        { "LOCAL5", LOG_LOCAL5 }, { "local6", LOG_LOCAL6 }, { "local7", LOG_LOCAL7 },
    };
    for (size_t i = 0; i < sizeof(facs) / sizeof(facs[0]); i++) {
        char txt[200];
        snprintf(txt, sizeof(txt), "logging { channel c { syslog %s; }; };", facs[i].name);
        if (ok_with(facs[i].name, txt, "", &cfg)) {
            const log_channel_t *c = find_channel(&cfg, "c");
            CHECK_MSG(c && c->syslog_facility == facs[i].fac, "facility %s", facs[i].name);
            free_server_config_fields(&cfg);
        }
    }
    if (ok_with("unknown facility", "logging {\n channel c { syslog nosuch; };\n};", "[WARNING]|line 2|unknown facility 'nosuch'; daemon is used", &cfg)) {
        const log_channel_t *c = find_channel(&cfg, "c");
        CHECK(c && c->syslog_facility == LOG_DAEMON);
        free_server_config_fields(&cfg);
    }

    /* file clauses: any order, "unlimited" / "default" sizes, the old "MB" spelling, versions 0 */
    if (ok_with("file clause order", "logging { channel c { file \"/tmp/c\" suffix increment size 1g versions 0; }; };", "", &cfg)) {
        const log_channel_t *c = find_channel(&cfg, "c");
        CHECK(c && c->versions == 0 && c->size_limit == 1024ULL * 1024 * 1024 && !c->suffix_timestamp);
        free_server_config_fields(&cfg);
    }
    if (ok_with("size unlimited", "logging { channel c { file \"/tmp/c\" size unlimited; }; channel d { file \"/tmp/d\" size default; }; };", "", &cfg)) {
        const log_channel_t *c = find_channel(&cfg, "c"), *d = find_channel(&cfg, "d");
        CHECK(c && c->size_limit == 0 && d && d->size_limit == 0);
        free_server_config_fields(&cfg);
    }
    /* a size BIND does not take */
    expect_an_error("size 0x10", "logging { channel c { file \"/tmp/c\" size 0x10; }; };", "invalid size value '0x10'");
    expect_an_error("size 1t", "logging { channel c { file \"/tmp/c\" size 1t; }; };", "invalid size value '1t'");
    expect_an_error("size B only", "logging { channel c { file \"/tmp/c\" size 10B; }; };", "invalid size value '10B'");
    expect_an_error("size too big", "logging { channel c { file \"/tmp/c\" size 99999999999999999999; }; };", "invalid size value");
    expect_an_error("versions text", "logging { channel c { file \"/tmp/c\" versions many; }; };", "invalid versions value 'many'");
    expect_an_error("suffix text", "logging { channel c { file \"/tmp/c\" suffix serial; }; };", "invalid suffix 'serial'");
    expect_an_error("file option twice", "logging { channel c { file \"/tmp/c\" size 1m size 2m; }; };", "'size' is given twice");
    expect_an_error("file option unknown", "logging { channel c { file \"/tmp/c\" rotate 3; }; };", "file: unknown option 'rotate'");
    expect_an_error("file path missing", "logging { channel c { file; }; };", "expected a file name");
    expect_an_error("file path empty", "logging { channel c { file \"\"; }; };", "the file name is empty");
    expect_an_error("file ';' missing", "logging { channel c { file \"/tmp/c\" versions 3 }; };", "file: expected versions, size, suffix or ';'");

    /* the shape of a channel */
    expect_an_error("no destination", "logging {\n channel c { severity info; };\n};", "line 2|channel 'c'|exactly one of file, syslog, null, and stderr must be present");
    expect_an_error("file and null", "logging { channel c { file \"/tmp/c\"; null; }; };", "exactly one of file, syslog, null, and stderr must be present");
    expect_an_error("stderr and stderr", "logging { channel c { stderr; stderr; }; };", "exactly one of");
    expect_an_error("clause twice", "logging { channel c { null; severity info; severity error; }; };", "'severity' is given twice");
    expect_an_error("print-time twice", "logging { channel c { null; print-time yes; print-time no; }; };", "'print-time' is given twice");
    expect_an_error("print-severity twice", "logging { channel c { null; print-severity yes; print-severity no; }; };", "'print-severity' is given twice");
    expect_an_error("print-category twice", "logging { channel c { null; print-category yes; print-category no; }; };", "'print-category' is given twice");
    expect_an_error("buffered twice", "logging { channel c { null; buffered yes; buffered no; }; };", "'buffered' is given twice");
    expect_an_error("print-severity value", "logging { channel c { null; print-severity maybe; }; };", "print-severity: invalid value 'maybe'");
    expect_an_error("unknown channel option", "logging {\n channel c {\n null;\n rotate yes;\n };\n};", "line 4|channel 'c'|unknown option 'rotate'");
    expect_an_error("channel without name", "logging { channel { null; }; };", "expected a channel name");
    expect_an_error("channel without '{'", "logging { channel c null; };", "expected '{' but found 'null'");
    expect_an_error("channel ';' missing", "logging { channel c { null; } };", "expected ';' after '}' but found '}'");
    expect_an_error("clause ';' missing", "logging { channel c { null } };", "expected ';' after null but found '}'");
    expect_an_error("channel end of file", "logging { channel c { null; ", "expected a channel option or '}' but found end of file");
    expect_an_error("severity ';' missing", "logging { channel c { null; severity info }; };", "expected ';' after the severity");
    expect_an_error("statement is a number", "logging { 1 };", "unknown statement '1'");
    expect_an_error("statement is a block", "logging { { }; };", "expected 'channel', 'category' or '}' but found '{'");
    expect_an_error("logging ';' missing", "logging { }", "expected ';' after '}' but found end of file");
    expect_an_error("logging without '{'", "logging;", "logging: expected '{' but found ';'");
    expect_an_error("max-qps negative", "logging { channel c { null; max-qps -1; }; };", "max-qps: invalid value '-1'");

    /* categories: the names of BIND 9.20.4, nothing else; channels must exist (built-in ones included) */
    {
        static const char *const cats[] = {
            "default", "general", "sslkeylog", "notify", "database", "security", "dnssec", "resolver", "xfer-in", "xfer-out", "dispatch",
            "lame-servers", "edns-disabled", "rpz", "rate-limit", "cname", "spill", "dnstap", "zoneload", "nsid", "rpz-passthru", "client",
            "network", "update", "queries", "update-security", "query-errors", "trust-anchor-telemetry", "serve-stale", "responses", "config",
            "unmatched",
        };
        CHECK(sizeof(cats) / sizeof(cats[0]) == LOGC_COUNT);
        for (size_t i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
            char txt[200];
            snprintf(txt, sizeof(txt), "logging { category %s { null; }; };", cats[i]);
            if (ok_with(cats[i], txt, "", &cfg)) {
                int c = log_category_from_name(cats[i]);
                CHECK_MSG(c >= 0 && strcmp(log_category_names[c], cats[i]) == 0 && cfg.logging.cat[c].n == 1, "category %s", cats[i]);
                free_server_config_fields(&cfg);
            }
        }
    }
    CHECK(log_category_from_name("_placeholder") < 0 && log_category_from_name("Queries") < 0 && log_category_from_name(NULL) < 0);
    expect_an_error("undefined category", "logging {\n category delegation-only { null; };\n};", "line 2|undefined category: 'delegation-only'");
    expect_an_error("undefined channel", "logging {\n channel a { null; };\n category queries {\n a;\n nosuch;\n };\n};", "line 5|undefined channel: 'nosuch'");
    expect_an_error("undefined channel in an empty logging statement", "logging { category default { default_syslog; nosuch_one; }; };", "undefined channel: 'nosuch_one'");
    expect_an_error("category name missing", "logging { category { null; }; };", "expected a category name");
    expect_an_error("category without '{'", "logging { category queries null; };", "expected '{' but found 'null'");
    expect_an_error("category channel ';' missing", "logging { category queries { null }; };", "expected ';' after the channel name but found '}'");
    expect_an_error("category end ';' missing", "logging { category queries { null; } };", "expected ';' after '}' but found '}'");
    expect_an_error("category list is a block", "logging { category queries { { }; }; };", "expected a channel name or '}' but found '{'");
    {
        /* LOG_ROUTE_MAX channels are the most a category can write to */
        char txt[1024] = "logging { ";
        for (int i = 0; i < LOG_ROUTE_MAX + 1; i++) {
            char one[64];
            snprintf(one, sizeof(one), "channel n%d { null; }; ", i);
            strcat(txt, one);
        }
        strcat(txt, "category default { ");
        for (int i = 0; i < LOG_ROUTE_MAX; i++) {
            char one[32];
            snprintf(one, sizeof(one), "n%d; ", i);
            strcat(txt, one);
        }
        strcat(txt, "}; };");
        if (ok_with("the most channels", txt, "", &cfg)) {
            CHECK(cfg.logging.cat[LOGC_DEFAULT].n == LOG_ROUTE_MAX);
            free_server_config_fields(&cfg);
        }
        txt[strlen(txt) - 5] = '\0';
        strcat(txt, "n8; }; };");
        expect_an_error("one channel too many", txt, "more than 8 channels");
    }

    /* warnings: accepted, with the place */
    if (ok_with("buffered yes", "logging {\n channel c { null; buffered yes; };\n};", "[WARNING]|line 2|buffered is accepted but has no effect", &cfg))
        free_server_config_fields(&cfg);
    if (ok_with("size without versions", "logging {\n channel c { file \"/tmp/c\" size 1m; };\n};",
                "[WARNING]|line 2|channel 'c'|size without versions: when the file is full no more lines are written", &cfg))
        free_server_config_fields(&cfg);
    expect_silent("size with versions", "logging { channel c { file \"/tmp/c\" size 1m versions 2; }; };", &cfg);
    free_server_config_fields(&cfg);
    expect_silent("size with a timestamp suffix", "logging { channel c { file \"/tmp/c\" size 1m suffix timestamp; }; };", &cfg);
    free_server_config_fields(&cfg);
    if (ok_with("channel defined twice", "logging {\n channel c { null; };\n channel c { stderr; };\n category default { c; };\n};",
                "[WARNING]|line 3|the channel is defined twice; the later definition is used", &cfg)) {
        CHECK(find_channel(&cfg, "c") && find_channel(&cfg, "c")->dest == LOGDEST_STDERR);   /* the newest is found first (BIND prepends) */
        free_server_config_fields(&cfg);
    }
    if (ok_with("built-in channel replaced", "logging {\n channel default_syslog { syslog local3; };\n};", "[WARNING]|line 2|replaces the built-in channel", &cfg))
        free_server_config_fields(&cfg);
    if (ok_with("second logging statement", "logging { channel a { null; }; };\nlogging { channel b { null; }; category default { a; b; }; };",
                "[WARNING]|line 2|a second logging statement", &cfg)) {
        CHECK(find_channel(&cfg, "a") && find_channel(&cfg, "b") && cfg.logging.cat[LOGC_DEFAULT].n == 2);
        free_server_config_fields(&cfg);
    }
    if (ok_with("channel listed twice", "logging { channel a { null; }; category default { a; a; }; };", "[WARNING]|channel 'a' is listed twice", &cfg)) {
        CHECK(cfg.logging.cat[LOGC_DEFAULT].n == 1);
        free_server_config_fields(&cfg);
    }
    expect_silent("empty logging", "logging { };", &cfg);
    free_server_config_fields(&cfg);

    /* querylog and the switches the query path reads */
    expect_silent("querylog yes", "options { querylog yes; };", &cfg);
    CHECK(cfg.querylog_set && cfg.querylog && cfg.logging.queries_enabled && !cfg.logging.responses_enabled);
    free_server_config_fields(&cfg);
    expect_silent("querylog no with a category", "options { querylog no; }; logging { channel q { file \"/tmp/q\"; }; category queries { q; }; };", &cfg);
    CHECK(cfg.querylog_set && !cfg.querylog && !cfg.logging.queries_enabled && cfg.logging.queries_channel);   /* querylog decides on / off only */
    free_server_config_fields(&cfg);
    expect_silent("category queries alone", "logging { channel q { file \"/tmp/q\"; }; category queries { q; }; };", &cfg);
    CHECK(!cfg.querylog_set && cfg.logging.queries_enabled);                        /* as KariDNS always did */
    free_server_config_fields(&cfg);
    expect_silent("a built-in channel for queries", "options { querylog yes; }; logging { category queries { default_stderr; }; };", &cfg);
    CHECK(cfg.logging.queries_enabled && cfg.logging.queries_channel == NULL && cfg.logging.queries_channel_name &&
          strcmp(cfg.logging.queries_channel_name, "default_stderr") == 0);
    free_server_config_fields(&cfg);
    expect_silent("nothing", "options { };", &cfg);
    CHECK(!cfg.querylog_set && !cfg.logging.queries_enabled && !cfg.logging.responses_enabled);
    free_server_config_fields(&cfg);
    expect_silent("a reload into the same struct forgets the querylog", "options { querylog yes; };", &cfg);
    free_server_config_fields(&cfg);
    expect_silent("second parse", "options { };", &cfg);
    CHECK(!cfg.querylog_set && !cfg.logging.queries_enabled);
    free_server_config_fields(&cfg);
    expect_an_error("querylog value", "options { querylog maybe; };", "querylog");

    /* controls { }: BIND's rndc channel.  Checked, then ignored with a warning (karictl has control-channel) */
    expect_silent("empty controls", "controls { };", &cfg);
    CHECK(cfg.controls_count == 0);
    free_server_config_fields(&cfg);
    if (ok_with("the controls BIND ships",
                "key \"rndc-key\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; };\n"
                "controls {\n inet 127.0.0.1 allow { localhost; } keys { rndc-key; };\n};\n",
                "[WARNING]|line 3|inet 127.0.0.1 port 953: rndc is not supported|has no effect", &cfg)) {
        CHECK(cfg.controls_count == 1 && cfg.controls[0].nkeys == 1 && strcmp(cfg.controls[0].keys[0], "rndc-key") == 0 && cfg.controls[0].port == 0);
        free_server_config_fields(&cfg);
    }
    if (ok_with("all the options of an entry",
                "key k { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTIzNDU2\"; };\nacl trusted { 192.0.2.0/24; };\n"
                "controls { inet * port 9953 allow { trusted; !192.0.2.9; 2001:db8::/32; } keys { k; K; } read-only yes;\n"
                "           inet ::1 port * allow { none; } read-only no;\n"
                "           inet 192.0.2.1 allow { any; } keys { }; };\n"
                "controls { inet 192.0.2.2 port 953 allow { any; }; };",
                "[WARNING]|inet 0.0.0.0 port 9953|inet ::1 port 953|inet 192.0.2.2 port 953", &cfg)) {
        CHECK(cfg.controls_count == 4 && cfg.controls[0].port == 9953 && cfg.controls[0].nkeys == 2 && strcmp(cfg.controls[0].addr, "0.0.0.0") == 0);
        CHECK(cfg.controls[1].port == 0 && strcmp(cfg.controls[1].addr, "::1") == 0 && cfg.controls[2].nkeys == 0);
        free_server_config_fields(&cfg);
    }
    expect_an_error("unix control", "controls {\n unix \"/var/run/named.sock\" perm 0600 owner 0 group 0;\n};", "line 2|controls|unix control '/var/run/named.sock': not supported");
    expect_an_error("controls address", "controls { inet nosuchhost allow { any; }; };", "inet: 'nosuchhost' is not an IPv4 or IPv6 address");
    expect_an_error("controls allow missing", "controls { inet 127.0.0.1; };", "inet 127.0.0.1: expected 'allow' but found ';'");
    expect_an_error("controls port", "controls { inet 127.0.0.1 port 70000 allow { any; }; };", "invalid port '70000'");
    expect_an_error("controls port text", "controls { inet 127.0.0.1 port ssh allow { any; }; };", "invalid port 'ssh'");
    expect_an_error("controls allow list", "controls { inet 127.0.0.1 allow any; };", "expected '{' after allow but found 'any'");
    expect_an_error("controls allow acl", "controls {\n inet 127.0.0.1 allow { nosuchacl; };\n};", "line 2|nosuchacl");
    expect_an_error("controls keys order", "controls { inet 127.0.0.1 allow { any; } read-only yes keys { k; }; };", "inet 127.0.0.1: expected ';' but found 'keys'");
    expect_an_error("controls keys twice", "controls { inet 127.0.0.1 allow { any; } keys { } keys { }; };", "inet 127.0.0.1: expected 'read-only' or ';' but found 'keys'");
    expect_an_error("controls read-only value", "controls { inet 127.0.0.1 allow { any; } read-only perhaps; };", "read-only: invalid value 'perhaps'");
    expect_an_error("controls keys block", "controls { inet 127.0.0.1 allow { any; } keys k; };", "expected '{' after keys but found 'k'");
    expect_an_error("controls key ';' missing", "controls { inet 127.0.0.1 allow { any; } keys { k }; };", "expected ';' after the key name");
    expect_an_error("controls unknown key", "controls {\n inet 127.0.0.1 allow { any; } keys {\n  nosuchkey;\n };\n};", "line 3|controls|unknown key 'nosuchkey'");
    expect_an_error("controls duplicate", "controls {\n inet 127.0.0.1 allow { any; };\n inet 127.0.0.1 port 953 allow { none; };\n};", "line 3|inet control socket '127.0.0.1#953': already defined, previous definition: line 2");
    expect_an_error("controls statement", "controls { snail 1; };", "unknown statement 'snail' (expected inet or unix)");
    expect_an_error("controls list is a block", "controls { { }; };", "expected 'inet' or '}' but found '{'");
    expect_an_error("controls without '{'", "controls;", "controls: expected '{' but found ';'");
    expect_an_error("controls ';' missing", "controls { }", "expected ';' after '}'");
    expect_an_error("controls entry ';' missing", "controls { inet 127.0.0.1 allow { any; } }", "inet 127.0.0.1: expected 'keys', 'read-only' or ';' but found '}'");

    /* statistics-channels: not implemented, accepted with a warning, whatever it holds */
    if (ok_with("statistics-channels", "statistics-channels {\n inet 127.0.0.1 port 8053 allow { 127.0.0.1; };\n};\noptions { port 5300; };",
                "[WARNING]|line 1|statistics-channels|no statistics channel", &cfg)) {
        CHECK(cfg.port == 5300);
        free_server_config_fields(&cfg);
    }
}

/* ---- BIND compatibility, batch 7: option values.  Expectations from the BIND 9.20.4 source (bin/named/server.c, lib/isccfg/namedconf.c,
 * lib/isccfg/check.c, bin/named/zoneconf.c) as quoted at each block; the decisions on KariDNS's own units are in the docs. ---- */
static void test_bind_option_values_tcp(void) {
    server_config_t cfg;
    /* bin/named/server.c: tcp-initial-timeout / tcp-idle-timeout / tcp-keepalive-timeout / tcp-advertised-timeout are in units of 100 ms */
    if (ok_with("bare units", "options { tcp-initial-timeout 100; tcp-idle-timeout 300; };", "", &cfg)) {
        CHECK(cfg.tcp_initial_timeout == 10000 && cfg.tcp_idle_timeout == 30000);
        free_server_config_fields(&cfg);
    }
    /* the KariDNS spelling in milliseconds, unchanged; 0ms is "the default" (the server uses 10000) */
    if (ok_with("ms suffix", "options { tcp-initial-timeout 1500ms; tcp-idle-timeout 2MS; };", "", &cfg)) {
        CHECK(cfg.tcp_initial_timeout == 1500 && cfg.tcp_idle_timeout == 2);
        free_server_config_fields(&cfg);
    }
    if (ok_with("0ms", "options { tcp-idle-timeout 0ms; };", "", &cfg)) {
        CHECK(cfg.tcp_idle_timeout == 0);
        free_server_config_fields(&cfg);
    }
    /* the largest bare value BIND takes (MAX_*_TIMEOUT 120000 ms) */
    if (ok_with("max", "options { tcp-initial-timeout 1200; tcp-idle-timeout 1200; };", "", &cfg)) {
        CHECK(cfg.tcp_initial_timeout == 120000 && cfg.tcp_idle_timeout == 120000);
        free_server_config_fields(&cfg);
    }
    /* BIND raises a value below the minimum (MIN_INITIAL_TIMEOUT 2500 ms, MIN_IDLE_TIMEOUT 100 ms) with a warning */
    if (ok_with("raised", "options { tcp-initial-timeout 10; tcp-idle-timeout 0; };",
                "line 1|tcp-initial-timeout: value is out of range: raising to 25|tcp-idle-timeout: value is out of range: raising to 1", &cfg)) {
        CHECK(cfg.tcp_initial_timeout == 2500 && cfg.tcp_idle_timeout == 100);
        free_server_config_fields(&cfg);
    }
    /* a bare value above 1200 is an old millisecond value: an error that names the suffix (decision plan A) */
    expect_an_error("idle 10000", "options { tcp-idle-timeout 10000; };", "line 1|tcp-idle-timeout|10000 is more than the maximum of 1200|write 10000ms");
    expect_an_error("initial 1201", "options {\n tcp-initial-timeout 1201;\n};", "line 2|tcp-initial-timeout|write 1201ms");
    expect_an_error("not a number", "options { tcp-idle-timeout 12x; };", "invalid value '12x'");
    expect_an_error("negative", "options { tcp-idle-timeout -1; };", "invalid value '-1'");
    expect_an_error("too big", "options { tcp-idle-timeout 4294967296ms; };", "invalid value");
    expect_an_error("empty ms", "options { tcp-idle-timeout ms; };", "invalid value 'ms'");
    expect_an_error("no semicolon", "options { tcp-idle-timeout 5 };", "");
    /* tcp-advertised-timeout: no minimum; above 65535 BIND lowers it; tcp-keepalive-timeout is accepted with a note */
    if (ok_with("advertised", "options { tcp-advertised-timeout 300; };", "", &cfg)) {
        CHECK(cfg.tcp_advertised_set && cfg.tcp_advertised_units == 300);
        free_server_config_fields(&cfg);
    }
    if (ok_with("advertised 0", "options { tcp-advertised-timeout 0; };", "", &cfg)) {
        CHECK(cfg.tcp_advertised_set && cfg.tcp_advertised_units == 0);
        free_server_config_fields(&cfg);
    }
    if (ok_with("advertised max", "options { tcp-advertised-timeout 70000; tcp-keepalive-timeout 0; };",
                "tcp-advertised-timeout: value is out of range: lowering to 65535|tcp-keepalive-timeout: value is out of range: raising to 1|"
                "tcp-keepalive-timeout: accepted, no effect", &cfg)) {
        CHECK(cfg.tcp_advertised_units == 65535);
        free_server_config_fields(&cfg);
    }
    if (ok_with("advertised ms", "options { tcp-advertised-timeout 5000ms; };", "", &cfg)) {
        CHECK(cfg.tcp_advertised_units == 50);
        free_server_config_fields(&cfg);
    }
    if (ok_with("advertised ms big", "options { tcp-advertised-timeout 4294967295ms; };", "", &cfg)) {
        CHECK(cfg.tcp_advertised_units == 65535);
        free_server_config_fields(&cfg);
    }
    expect_an_error("keepalive junk", "options { tcp-keepalive-timeout x; };", "invalid value 'x'");
}

/* minimal-responses (namedconf.c: ( no-auth | no-auth-recursive | <boolean> )), version / hostname / server-id (qstringornone, serverid) */
static void test_bind_option_values_minimal_chaos(void) {
    server_config_t cfg;
    static const struct { const char *text; int mode; } mr[] = {
        { "yes", MINIMAL_YES }, { "no", MINIMAL_NO }, { "true", MINIMAL_YES }, { "false", MINIMAL_NO }, { "1", MINIMAL_YES }, { "0", MINIMAL_NO },
        { "no-auth", MINIMAL_NO_AUTH }, { "NO-AUTH", MINIMAL_NO_AUTH }, { "no-auth-recursive", MINIMAL_NO_AUTH_RECURSIVE },
        { "No-Auth-Recursive", MINIMAL_NO_AUTH_RECURSIVE },
    };
    for (size_t i = 0; i < sizeof(mr) / sizeof(mr[0]); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "options { minimal-responses %s; };", mr[i].text);
        if (ok_with(mr[i].text, txt, "", &cfg)) {
            CHECK_MSG(cfg.minimal_responses == mr[i].mode, "minimal-responses %s", mr[i].text);
            free_server_config_fields(&cfg);
        }
    }
    expect_an_error("minimal-responses word", "options { minimal-responses auth; };", "line 1|minimal-responses: invalid value 'auth'|no-auth-recursive");
    expect_an_error("minimal-responses semicolon", "options { minimal-responses no-auth };", "");

    /* version / hostname / server-id */
    if (ok_with("chaos texts", "options { version \"v1\"; hostname \"h1\"; server-id \"s1\"; };", "", &cfg)) {
        CHECK(cfg.chaos.version_set && !cfg.chaos.version_none && strcmp(cfg.chaos.r_version, "v1") == 0 && cfg.chaos.has_version);
        CHECK(cfg.chaos.hostname_set && strcmp(cfg.chaos.r_hostname, "h1") == 0 && cfg.chaos.has_hostname);
        CHECK(cfg.chaos.server_id_set && !cfg.chaos.server_id_hostname && strcmp(cfg.chaos.r_id, "s1") == 0 && cfg.chaos.has_id);
        CHECK(cfg.nsid_string && strcmp(cfg.nsid_string, "s1") == 0);
        free_server_config_fields(&cfg);
    }
    if (ok_with("chaos none", "options { version none; hostname none; server-id none; };", "", &cfg)) {
        CHECK(cfg.chaos.version_none && !cfg.chaos.has_version && cfg.chaos.hostname_none && !cfg.chaos.has_hostname);
        CHECK(cfg.chaos.server_id_none && !cfg.chaos.has_id && cfg.nsid_string == NULL);
        free_server_config_fields(&cfg);
    }
    /* a quoted "none" / "hostname" is the text, not the keyword (the BIND lexer returns a quoted string as a different token) */
    if (ok_with("quoted keywords", "options { version \"none\"; server-id \"hostname\"; };", "", &cfg)) {
        CHECK(!cfg.chaos.version_none && strcmp(cfg.chaos.r_version, "none") == 0);
        CHECK(!cfg.chaos.server_id_hostname && strcmp(cfg.chaos.r_id, "hostname") == 0);
        free_server_config_fields(&cfg);
    }
    /* the same text for nsid and server-id is fine; a different one is a mistake (server-id is the NSID) */
    if (ok_with("nsid and server-id agree", "options { nsid \"n\"; server-id \"n\"; };", "", &cfg)) free_server_config_fields(&cfg);
    expect_an_error("nsid differs", "options { server-id \"a\"; nsid \"b\"; };", "server-id 'a'|nsid says 'b'");
    expect_an_error("hostname needs a value", "options { version; };", "");
    expect_an_error("server-id semicolon", "options { server-id hostname };", "");
    expect_an_error("version semicolon", "options { version none };", "");
}

/* max-records, max-records-per-type, max-types-per-name, max-zone-ttl, serial-update-method, masterfile-format, check-*: grammar from BIND 9.20.4
 * lib/isccfg/namedconf.c (cfg_type_uint32, cfg_type_maxduration, cfg_type_updatemethod, masterformat_enums, checkmode_enums, warn_enums,
 * checknames_fields); the zone > view > options precedence of named_config_get() maps; defaults of bin/named/config.c. */
static void test_bind_option_values_zone(void) {
    server_config_t cfg;
    zone_veff_t v;
    zone_limits_t lim;
    /* nothing written: no limits, increment, every check CHK_DEFAULT */
    if (ok_with("none", "options { }; zone \"z.test\" { type master; file \"z\"; };", "", &cfg)) {
        zone_vopts_effective(&cfg, first_zone(&cfg), "__default__", &v);
        CHECK(v.max_records == 0 && v.max_per_type == 0 && v.max_types_per_name == 0 && v.max_zone_ttl == 0 && v.serial_method == SUM_INCREMENT);
        for (int i = 0; i < ZC_N; i++) CHECK(v.chk[i] == CHK_DEFAULT);
        CHECK(v.check_names == CHK_DEFAULT);
        free_server_config_fields(&cfg);
    }
    /* options < view < zone, statement by statement */
    if (ok_with("levels",
                "options { max-records 100; max-records-per-type 10; max-types-per-name 20; max-zone-ttl 1d; serial-update-method date; };\n"
                "view v1 { match-clients { any; }; max-records 50; max-zone-ttl unlimited; serial-update-method unixtime;\n"
                "  zone \"a.test\" { type master; file \"a\"; max-records 7; max-records-per-type 3; };\n"
                "  zone \"b.test\" { type master; file \"b\"; }; };", "", &cfg)) {
        const view_config_t *vw = cfg.views;
        zone_config_t *za = view_find_zone_config(vw, "a.test"), *zb = view_find_zone_config(vw, "b.test");
        CHECK(za && zb);
        zone_vopts_effective(&cfg, za, "v1", &v);
        CHECK(v.max_records == 7 && v.max_per_type == 3 && v.max_types_per_name == 20 && v.max_zone_ttl == 0 && v.serial_method == SUM_UNIXTIME);
        zone_vopts_effective(&cfg, zb, "v1", &v);
        CHECK(v.max_records == 50 && v.max_per_type == 10 && v.max_zone_ttl == 0);
        zone_vopts_effective(&cfg, zb, "other", &v);   /* a view that does not exist: options only */
        CHECK(v.max_records == 100 && v.max_zone_ttl == 86400 && v.serial_method == SUM_DATE);
        zone_limits_effective(&cfg, za, "v1", &lim);
        CHECK(lim.max_records == 7 && lim.max_per_type == 3 && lim.max_types_per_name == 20 && lim.max_zone_ttl == 0);
        zone_limits_effective(&cfg, NULL, NULL, &lim);
        CHECK(lim.max_records == 100 && lim.max_zone_ttl == 86400);
        free_server_config_fields(&cfg);
    }
    /* max-zone-ttl is a primary zone's option: a secondary zone is not held to it */
    if (ok_with("ttl by type", "options { max-zone-ttl 3600; }; zone \"s.test\" { type secondary; primaries { 192.0.2.1; }; };", "", &cfg)) {
        zone_limits_effective(&cfg, first_zone(&cfg), "__default__", &lim);
        CHECK(lim.max_zone_ttl == 0);
        free_server_config_fields(&cfg);
    }
    /* max-zone-ttl values: seconds, units, unlimited; ISO 8601 and junk are refused with the reason */
    static const struct { const char *text; uint32_t secs; } ttls[] = { {"0", 0}, {"3600", 3600}, {"1h", 3600}, {"1w", 604800}, {"1h30m", 5400}, {"unlimited", 0}, {"UNLIMITED", 0} };
    for (size_t i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "options { max-zone-ttl %s; };", ttls[i].text);
        if (ok_with(ttls[i].text, txt, "", &cfg)) {
            CHECK_MSG(cfg.zv.max_zone_ttl == ttls[i].secs && (cfg.zv.set & ZV_MAX_ZONE_TTL), "max-zone-ttl %s", ttls[i].text);
            free_server_config_fields(&cfg);
        }
    }
    expect_an_error("iso8601", "options { max-zone-ttl P1D; };", "line 1|max-zone-ttl: ISO 8601 durations|not supported");
    expect_an_error("ttl junk", "options { max-zone-ttl 1x; };", "max-zone-ttl: invalid value '1x'");
    /* the counts: 0 .. 4294967295 */
    if (ok_with("counts max", "options { max-records 4294967295; max-records-per-type 0; max-types-per-name 1; };", "", &cfg)) {
        CHECK(cfg.zv.max_records == 4294967295u && cfg.zv.max_per_type == 0 && cfg.zv.max_types_per_name == 1);
        CHECK((cfg.zv.set & (ZV_MAX_RECORDS | ZV_MAX_PER_TYPE | ZV_MAX_TYPES_PER_NAME)) == (ZV_MAX_RECORDS | ZV_MAX_PER_TYPE | ZV_MAX_TYPES_PER_NAME));
        free_server_config_fields(&cfg);
    }
    expect_an_error("count too big", "options { max-records 4294967296; };", "max-records: invalid value");
    expect_an_error("count negative", "options { max-records-per-type -1; };", "max-records-per-type: invalid value");
    expect_an_error("count text", "options { max-types-per-name many; };", "max-types-per-name: invalid value");
    expect_an_error("zone count", "zone \"z.test\" { type master; file \"z\"; max-records x; };", "zone 'z.test.'|max-records: invalid value");
    expect_an_error("view count", "view v { match-clients { any; }; max-records x; };", "view 'v'|max-records: invalid value");
    /* serial-update-method */
    static const struct { const char *text; int m; } sums[] = { {"increment", SUM_INCREMENT}, {"unixtime", SUM_UNIXTIME}, {"date", SUM_DATE}, {"DATE", SUM_DATE} };
    for (size_t i = 0; i < sizeof(sums) / sizeof(sums[0]); i++) {
        char txt[128];
        snprintf(txt, sizeof(txt), "options { serial-update-method %s; };", sums[i].text);
        if (ok_with(sums[i].text, txt, "", &cfg)) {
            CHECK_MSG(cfg.zv.serial_method == sums[i].m, "serial-update-method %s", sums[i].text);
            free_server_config_fields(&cfg);
        }
    }
    expect_an_error("serial method", "zone \"z.test\" { type master; file \"z\"; serial-update-method epoch; };", "serial-update-method: invalid value 'epoch'|increment, unixtime or date");
    /* masterfile-format: text is read, raw is refused clearly (no silent text read of a raw file) */
    if (ok_with("masterfile text", "options { masterfile-format text; }; zone \"z.test\" { type master; file \"z\"; masterfile-format TEXT; };", "", &cfg))
        free_server_config_fields(&cfg);
    expect_an_error("masterfile raw", "options { masterfile-format raw; };", "line 1|masterfile-format raw is not supported|text format only");
    expect_an_error("masterfile raw zone", "zone \"z.test\" { type secondary; primaries { 192.0.2.1; }; file \"z\"; masterfile-format raw; };", "zone 'z.test.'|masterfile-format raw is not supported");
    expect_an_error("masterfile map", "view v { match-clients { any; }; masterfile-format map; };", "masterfile-format: invalid value 'map'");
    /* the check-* family */
    if (ok_with("checks",
                "options { check-names primary ignore; check-names slave warn; check-names response fail; check-dup-records fail; check-mx ignore;\n"
                "  check-mx-cname warn; check-srv-cname ignore; check-integrity no; check-wildcard yes; check-sibling no; check-svcb no; check-spf ignore; };\n"
                "zone \"z.test\" { type master; file \"z\"; };\n", "check-sibling is accepted, no effect|check-svcb is accepted|check-spf is accepted", &cfg)) {
        zone_vopts_effective(&cfg, first_zone(&cfg), "__default__", &v);
        CHECK(v.chk[ZC_NAMES_PRIMARY] == CHK_IGNORE && v.chk[ZC_NAMES_SECONDARY] == CHK_WARN && v.chk[ZC_NAMES_RESPONSE] == CHK_FAIL);
        CHECK(v.chk[ZC_DUP_RECORDS] == CHK_FAIL && v.chk[ZC_MX] == CHK_IGNORE && v.chk[ZC_MX_CNAME] == CHK_WARN && v.chk[ZC_SRV_CNAME] == CHK_IGNORE);
        CHECK(v.chk[ZC_INTEGRITY] == CHK_IGNORE && v.chk[ZC_WILDCARD] == CHK_FAIL && v.chk[ZC_SIBLING] == CHK_IGNORE && v.chk[ZC_SVCB] == CHK_IGNORE);
        CHECK(v.chk[ZC_SPF] == CHK_IGNORE);
        CHECK(v.check_names == CHK_IGNORE);                 /* a primary zone takes check-names primary */
        free_server_config_fields(&cfg);
    }
    /* zone: check-names <mode> is the zone's own and wins; a secondary zone takes the secondary value of options */
    if (ok_with("zone check-names",
                "options { check-names primary fail; check-names secondary warn; };\n"
                "zone \"p.test\" { type master; file \"p\"; check-names ignore; };\n"
                "zone \"q.test\" { type master; file \"q\"; };\n"
                "zone \"s.test\" { type slave; primaries { 192.0.2.1; }; };\n", "", &cfg)) {
        zone_vopts_effective(&cfg, view_find_zone_config(cfg.views, "p.test"), "__default__", &v);
        CHECK(v.check_names == CHK_IGNORE);
        zone_vopts_effective(&cfg, view_find_zone_config(cfg.views, "q.test"), "__default__", &v);
        CHECK(v.check_names == CHK_FAIL);
        zone_vopts_effective(&cfg, view_find_zone_config(cfg.views, "s.test"), "__default__", &v);
        CHECK(v.check_names == CHK_WARN);
        free_server_config_fields(&cfg);
    }
    /* view-level check-* replace options' for its zones */
    if (ok_with("view checks", "options { check-mx fail; };\nview w { match-clients { any; }; check-mx ignore; check-names master warn; zone \"z.test\" { type master; file \"z\"; }; };", "", &cfg)) {
        zone_vopts_effective(&cfg, view_find_zone_config(cfg.views, "z.test"), "w", &v);
        CHECK(v.chk[ZC_MX] == CHK_IGNORE && v.check_names == CHK_WARN);
        free_server_config_fields(&cfg);
    }
    expect_an_error("check mode", "options { check-mx maybe; };", "check-mx: invalid value 'maybe'|fail, warn or ignore");
    expect_an_error("check bool", "options { check-integrity warn; };", "check-integrity: invalid value 'warn'|yes or no");
    expect_an_error("check spf", "options { check-spf fail; };", "check-spf: invalid value 'fail'|warn or ignore");
    expect_an_error("check-names type", "options { check-names nobody fail; };", "check-names: invalid type 'nobody'");
    expect_an_error("check-names mode", "options { check-names primary maybe; };", "check-names: invalid mode 'maybe'");
    expect_an_error("zone check-names", "zone \"z.test\" { type master; file \"z\"; check-names primary; };", "check-names: invalid mode 'primary'");
    expect_an_error("check semicolon", "options { check-mx warn };", "");
}

/* zone_arena_check_limits(): max-records, max-records-per-type, max-types-per-name and max-zone-ttl on a parsed and indexed zone */
static void test_bind_option_values_limits(void) {
    static char ztext[] =
        "$ORIGIN lim.test.\n$TTL 3600\n"
        "@ IN SOA ns1 admin 1 3600 1800 604800 86400\n"
        "@ IN NS ns1\n"
        "ns1 IN A 192.0.2.1\n"
        "www 300 IN A 192.0.2.10\n"
        "www 300 IN A 192.0.2.11\n"
        "www 300 IN A 192.0.2.12\n"
        "www IN TXT \"x\"\n"
        "www IN MX 10 ns1\n"
        "long 7200 IN A 192.0.2.20\n";
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t pc = { .base_dir = ".", .default_origin = "lim.test.", .is_standalone_mode = true, .err_out = &err };
    CHECK(parse_zone_fast(ztext, strlen(ztext), &arena, &pc) >= 0);
    CHECK(build_zone_index(&arena, true) == 0);
    char e[320];
    zone_limits_t l = {0};
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == 0);                  /* no limits */
    CHECK(zone_arena_check_limits(NULL, &l, e, sizeof(e)) == 0 && zone_arena_check_limits(&arena, NULL, e, sizeof(e)) == 0);
    l.max_records = 9;                                                              /* 9 RRs: SOA NS A A A A TXT MX A = 9 */
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == 0);
    l.max_records = 8;
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == -1 && strstr(e, "9 records") && strstr(e, "max-records 8"));
    memset(&l, 0, sizeof(l));
    l.max_per_type = 3;
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == 0);
    l.max_per_type = 2;
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == -1 && strstr(e, "www.lim.test.") && strstr(e, "3 records of type 1") && strstr(e, "max-records-per-type 2"));
    memset(&l, 0, sizeof(l));
    l.max_types_per_name = 3;                                                       /* www has A, TXT, MX */
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == 0);
    l.max_types_per_name = 2;
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == -1 && strstr(e, "www.lim.test.") && strstr(e, "3 record types") && strstr(e, "max-types-per-name 2"));
    memset(&l, 0, sizeof(l));
    l.max_zone_ttl = 7200;
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == 0);
    l.max_zone_ttl = 3600;
    CHECK(zone_arena_check_limits(&arena, &l, e, sizeof(e)) == -1 && strstr(e, "long.lim.test.") && strstr(e, "TTL 7200") && strstr(e, "max-zone-ttl 3600"));
    zone_arena_destroy(&arena);
    /* an arena without an index (no hash table): the per-name limits cannot be checked and are skipped; the counts still are */
    zone_arena_t bare;
    memset(&bare, 0, sizeof(bare));
    zone_arena_init(&bare);
    memset(&l, 0, sizeof(l));
    l.max_per_type = 1;
    CHECK(zone_arena_check_limits(&bare, &l, e, sizeof(e)) == 0);
    zone_arena_destroy(&bare);
}

/* BIND names of settings KariDNS has (udp-receive-buffer, udp-send-buffer, tcp-receive-buffer, tcp-send-buffer, max-udp-size), edns-udp-size,
 * require-server-cookie; BIND 9.20.4 bin/named/server.c (CAP_IF_NOT_ZERO(v, 4096, INT32_MAX); max-udp-size held to 512..4096) */
static void test_bind_option_values_aliases(void) {
    server_config_t cfg;
    if (ok_with("udp buffers", "options { udp-receive-buffer 65536; udp-send-buffer 32768; };", "", &cfg)) {
        CHECK(cfg.udp_recvbuf_size == 65536 && cfg.udp_sndbuf_size == 32768);
        free_server_config_fields(&cfg);
    }
    if (ok_with("udp buffer floor", "options { udp-receive-buffer 100; udp-send-buffer 0; };", "", &cfg)) {
        CHECK(cfg.udp_recvbuf_size == 4096);                    /* BIND raises a non-zero size to 4096 */
        CHECK(cfg.udp_sndbuf_size == 4 * 1024 * 1024);          /* 0 is the system's size: KariDNS keeps its own default */
        free_server_config_fields(&cfg);
    }
    if (ok_with("both names, one value", "options { udp-recvbuf-size 65536; udp-receive-buffer 65536; udp-sndbuf-size 8k; udp-send-buffer 8192; };", "", &cfg)) {
        CHECK(cfg.udp_recvbuf_size == 65536 && cfg.udp_sndbuf_size == 8192);
        free_server_config_fields(&cfg);
    }
    expect_an_error("recv conflict", "options {\n udp-recvbuf-size 65536;\n udp-receive-buffer 131072;\n};", "line 3|udp-receive-buffer 131072 and udp-recvbuf-size 65536|line 2|same setting");
    expect_an_error("send conflict", "options { udp-send-buffer 8192; udp-sndbuf-size 16384; };", "udp-sndbuf-size 16384 and udp-send-buffer 8192");
    if (ok_with("same name twice", "options { udp-receive-buffer 8192; udp-receive-buffer 16384; };", "", &cfg)) {
        CHECK(cfg.udp_recvbuf_size == 16384);
        free_server_config_fields(&cfg);
    }
    if (ok_with("tcp buffers", "options { tcp-window 65536; tcp-receive-buffer 131072; };", "", &cfg)) {
        CHECK(cfg_tcp_rcvbuf(&cfg) == 131072 && cfg_tcp_sndbuf(&cfg) == 65536);   /* a direction written replaces tcp-window for it */
        free_server_config_fields(&cfg);
    }
    if (ok_with("tcp send", "options { tcp-send-buffer 20000; };", "", &cfg)) {
        CHECK(cfg_tcp_rcvbuf(&cfg) == 0 && cfg_tcp_sndbuf(&cfg) == 20000);
        free_server_config_fields(&cfg);
    }
    expect_an_error("tcp buffer junk", "options { tcp-receive-buffer big; };", "tcp-receive-buffer");
    /* max-udp-size = udp-bufsize; BIND holds the value to 512..4096 */
    if (ok_with("max-udp-size", "options { max-udp-size 1400; };", "", &cfg)) {
        CHECK(cfg.udp_bufsize == 1400);
        free_server_config_fields(&cfg);
    }
    if (ok_with("max-udp-size clamp", "options { max-udp-size 100; };", "max-udp-size 100 is out of range (512..4096): raising to 512", &cfg)) {
        CHECK(cfg.udp_bufsize == 512);
        free_server_config_fields(&cfg);
    }
    if (ok_with("max-udp-size clamp up", "options { max-udp-size 9000; };", "max-udp-size 9000 is out of range (512..4096): lowering to 4096", &cfg)) {
        CHECK(cfg.udp_bufsize == 4096);
        free_server_config_fields(&cfg);
    }
    if (ok_with("udp-bufsize and max-udp-size agree", "options { udp-bufsize 1400; max-udp-size 1400; };", "", &cfg)) free_server_config_fields(&cfg);
    expect_an_error("udp size conflict", "options { udp-bufsize 1400; max-udp-size 1500; };", "max-udp-size 1500 and udp-bufsize 1400|same setting");
    expect_an_error("max-udp-size junk", "options { max-udp-size big; };", "max-udp-size");
    if (ok_with("edns-udp-size", "options { edns-udp-size 1232; };", "edns-udp-size: accepted, no effect", &cfg)) {
        CHECK(cfg.udp_bufsize == 0);                                         /* it is not the size of the responses */
        free_server_config_fields(&cfg);
    }
    /* view { max-udp-size; require-server-cookie; } */
    if (ok_with("view", "options { require-server-cookie yes; };\nview v { match-clients { any; }; max-udp-size 900; require-server-cookie no; };", "", &cfg)) {
        const view_config_t *vw = config_find_view(&cfg, "V");
        CHECK(vw && vw->max_udp_size == 900 && vw->require_cookie_set && !vw->require_cookie);
        CHECK(cfg.any_view_max_udp && cfg.any_view_cookie && cfg.require_server_cookie);
        CHECK(!config_require_server_cookie(&cfg, "v") && config_require_server_cookie(&cfg, "other") && config_require_server_cookie(&cfg, NULL));
        CHECK(config_find_view(&cfg, "") == NULL && config_find_view(&cfg, NULL) == NULL && config_find_view(NULL, "v") == NULL);
        CHECK(!config_require_server_cookie(NULL, "v"));
        free_server_config_fields(&cfg);
    }
    expect_an_error("view cookie value", "view v { match-clients { any; }; require-server-cookie maybe; };", "require-server-cookie");
    expect_an_error("view max-udp-size", "view v { match-clients { any; }; max-udp-size x; };", "max-udp-size");
    expect_an_error("cookie value", "options { require-server-cookie maybe; };", "require-server-cookie");
}

/* dnstap in the BIND 9.20 grammar (lib/isccfg/namedconf.c cfg_type_dnstap, dtout_fields; lib/isccfg/check.c check_dnstap(), the dnstap-output checks) */
static void test_bind_option_values_dnstap(void) {
    server_config_t cfg;
    if (ok_with("bind list", "options { dnstap { auth; }; dnstap-output unix \"/var/run/dnstap.sock\"; dnstap-identity \"id-1\"; dnstap-version \"v-1\"; };", "", &cfg)) {
        CHECK(cfg.dnstap.enabled && cfg.dnstap.bind_form && cfg.dnstap.log_auth_query && cfg.dnstap.log_auth_response);
        CHECK_STR(cfg.dnstap.socket_path, "/var/run/dnstap.sock");
        CHECK_STR(cfg.dnstap.identity, "id-1");
        CHECK_STR(cfg.dnstap.version, "v-1");
        free_server_config_fields(&cfg);
    }
    if (ok_with("auth query only", "options { dnstap { auth query; }; dnstap-output unix \"/s\"; };", "", &cfg)) {
        CHECK(cfg.dnstap.log_auth_query && !cfg.dnstap.log_auth_response);
        free_server_config_fields(&cfg);
    }
    if (ok_with("auth response, again", "options { dnstap { auth response; client query; }; dnstap-output unix \"/s\"; };", "client is accepted, no effect", &cfg)) {
        CHECK(!cfg.dnstap.log_auth_query && cfg.dnstap.log_auth_response);
        free_server_config_fields(&cfg);
    }
    if (ok_with("all and update", "options { dnstap { all response; update; resolver; forwarder; }; dnstap-output unix \"/s\"; };",
                "all: only the auth messages|update is accepted, no effect|resolver is accepted|forwarder is accepted", &cfg)) {
        CHECK(!cfg.dnstap.log_auth_query && cfg.dnstap.log_auth_response);
        free_server_config_fields(&cfg);
    }
    if (ok_with("only types KariDNS does not send", "options { dnstap { client; }; dnstap-output unix \"/s\"; };", "", &cfg)) {
        CHECK(cfg.dnstap.enabled && !cfg.dnstap.log_auth_query && !cfg.dnstap.log_auth_response);
        free_server_config_fields(&cfg);
    }
    if (ok_with("any order and case", "options { dnstap-output UNIX \"/s\"; dnstap { AUTH Query; }; dnstap-identity none; dnstap-version none; };", "", &cfg)) {
        CHECK(cfg.dnstap.log_auth_query && !cfg.dnstap.log_auth_response && cfg.dnstap.identity == NULL && cfg.dnstap.version == NULL);
        free_server_config_fields(&cfg);
    }
    if (ok_with("identity hostname", "options { dnstap-identity hostname; };", "", &cfg)) {
        char hn[256];
        CHECK(gethostname(hn, sizeof(hn)) == 0);
        hn[255] = 0;
        CHECK(cfg.dnstap.identity && strcmp(cfg.dnstap.identity, hn) == 0);
        free_server_config_fields(&cfg);
    }
    if (ok_with("quoted none", "options { dnstap-identity \"none\"; dnstap-version \"none\"; };", "", &cfg)) {
        CHECK_STR(cfg.dnstap.identity, "none");
        CHECK_STR(cfg.dnstap.version, "none");
        free_server_config_fields(&cfg);
    }
    if (ok_with("fstrm", "options { fstrm-set-buffer-hint 8192; fstrm-set-flush-timeout 1; fstrm-set-input-queue-size 512; fstrm-set-output-notify-threshold 32;\n"
                "  fstrm-set-output-queue-model mpsc; fstrm-set-output-queue-size 1024; fstrm-set-reopen-interval 5s; };", "fstrm-set-buffer-hint: accepted, no effect|fstrm-set-reopen-interval: accepted", &cfg))
        free_server_config_fields(&cfg);
    /* the KariDNS grammar keeps working, and its values agree with the BIND ones or the file is refused */
    if (ok_with("kariDNS form", "options { dnstap { socket \"/k\"; identity \"i\"; version \"v\"; queue-size 100; auth-query yes; auth-response no; }; };", "", &cfg)) {
        CHECK(!cfg.dnstap.bind_form && cfg.dnstap.log_auth_query && !cfg.dnstap.log_auth_response && cfg.dnstap.queue_size == 100);
        CHECK_STR(cfg.dnstap.socket_path, "/k");
        free_server_config_fields(&cfg);
    }
    if (ok_with("both forms, same values", "options { dnstap-output unix \"/k\"; dnstap { socket \"/k\"; }; dnstap-identity \"i\"; };", "", &cfg)) free_server_config_fields(&cfg);
    expect_an_error("socket differs", "options {\n dnstap-output unix \"/a\";\n dnstap { socket \"/b\"; };\n};", "line 3|dnstap: '/b' differs from '/a'|dnstap-output / dnstap-identity / dnstap-version");
    expect_an_error("identity differs", "options { dnstap { identity \"x\"; }; dnstap-identity \"y\"; };", "options dnstap-identity|'y' differs from 'x'");
    expect_an_error("version differs", "options { dnstap-version \"y\"; dnstap { version \"x\"; }; };", "dnstap: 'x' differs from 'y'");
    expect_an_error("mixed, bind first", "options { dnstap { auth; socket \"/s\"; }; dnstap-output unix \"/s\"; };", "'socket' is not a dnstap message type");
    expect_an_error("mixed, kariDNS first", "options { dnstap { socket \"/s\"; auth; }; };", "'auth' is a message type of the BIND list");
    expect_an_error("output required", "options { dnstap { auth; }; };", "'dnstap-output' must be set if 'dnstap' is set");
    expect_an_error("file output", "options { dnstap { auth; }; dnstap-output file \"/var/log/dnstap\" size 10m versions 3; };", "mode file is not supported|dnstap-output unix");
    expect_an_error("unix with size", "options { dnstap-output unix \"/s\" size 10m; };", "size, versions and suffix cannot be set with mode unix");
    expect_an_error("output mode", "options { dnstap-output tcp \"/s\"; };", "dnstap-output: invalid mode 'tcp'");
    expect_an_error("output junk", "options { dnstap-output unix \"/s\" nothing 1; };", "");
    expect_an_error("fstrm model", "options { fstrm-set-output-queue-model fifo; };", "fstrm-set-output-queue-model: invalid value 'fifo'");
    expect_an_error("fstrm number", "options { fstrm-set-buffer-hint -1; };", "fstrm-set-buffer-hint: invalid value");
    expect_an_error("fstrm interval", "options { fstrm-set-reopen-interval soon; };", "fstrm-set-reopen-interval: invalid value 'soon'");
    expect_an_error("type word", "options { dnstap { auth sometimes; }; dnstap-output unix \"/s\"; };", "");
    expect_an_error("identity semicolon", "options { dnstap-identity \"x\" };", "");
}

/* catalog-zones (BIND 9.20 lib/isccfg/namedconf.c catz_zone_fields; check.c check_catz(): each name once, default-primaries and default-masters not both) */
static void test_bind_option_values_catalog_zones(void) {
    server_config_t cfg;
    if (ok_with("options list",
                "options { catalog-zones { zone \"cat.test\" default-primaries { 192.0.2.1 port 5353 key k; 192.0.2.2; } zone-directory \"/x\" in-memory no min-update-interval 5m;\n"
                "  zone cat2.test; }; };\n"
                "zone \"cat.test\" { type secondary; primaries { 192.0.2.1; }; };\n"
                "zone \"cat2.test\" { type secondary; primaries { 192.0.2.1; }; };\n"
                "zone \"plain.test\" { type master; file \"p\"; };\n",
                "default-primaries is accepted, no effect|zone-directory is accepted|in-memory no is accepted|min-update-interval is accepted", &cfg)) {
        CHECK(view_find_zone_config(cfg.views, "cat.test")->is_catalog && view_find_zone_config(cfg.views, "cat2.test")->is_catalog);
        CHECK(!view_find_zone_config(cfg.views, "plain.test")->is_catalog);
        free_server_config_fields(&cfg);
    }
    /* the statement of a view marks the zones of that view only; in-memory yes is what KariDNS does anyway */
    if (ok_with("view list",
                "view a { match-clients { 192.0.2.0/24; }; catalog-zones { zone \"c.test\" in-memory yes; }; zone \"c.test\" { type secondary; primaries { 192.0.2.1; }; }; };\n"
                "view b { match-clients { any; }; zone \"c.test\" { type secondary; primaries { 192.0.2.1; }; }; };\n",
                "in-memory yes is how KariDNS always works", &cfg)) {
        CHECK(view_find_zone_config(cfg.views, "c.test")->is_catalog);
        CHECK(!view_find_zone_config(cfg.views->next, "c.test")->is_catalog);
        free_server_config_fields(&cfg);
    }
    /* a name that is no zone: said, not fatal */
    if (ok_with("no such zone", "options { catalog-zones { zone \"nothing.test\"; }; };\nview v { match-clients { any; }; catalog-zones { zone \"nope.test\"; }; };\n",
                "options catalog-zones: 'nothing.test' is not a zone|view catalog-zones: 'nope.test' is not a zone of view 'v'", &cfg))
        free_server_config_fields(&cfg);
    expect_an_error("twice", "options { catalog-zones { zone \"cat.test\"; zone \"CAT.test.\"; }; };", "catalog zone 'CAT.test.' is listed twice");
    expect_an_error("primaries and masters", "options { catalog-zones { zone \"c.test\" default-primaries { 192.0.2.1; } default-masters { 192.0.2.2; }; }; };",
                    "'default-primaries' and 'default-masters' can not be both defined");
    expect_an_error("not zone", "options { catalog-zones { member \"c.test\"; }; };", "expected `zone \"name\"`, found 'member'");
    expect_an_error("unknown option", "options { catalog-zones { zone \"c.test\" frobnicate yes; }; };", "unknown option 'frobnicate'");
    expect_an_error("bad bool", "options { catalog-zones { zone \"c.test\" in-memory sometimes; }; };", "invalid in-memory 'sometimes'");
    expect_an_error("bad interval", "options { catalog-zones { zone \"c.test\" min-update-interval soon; }; };", "invalid min-update-interval 'soon'");
    expect_an_error("unclosed list", "options { catalog-zones { zone \"c.test\" default-primaries { 192.0.2.1;", "");
    expect_an_error("no brace", "options { catalog-zones zone \"c.test\"; };", "");
    expect_an_error("name missing", "options { catalog-zones { zone ; }; };", "");
    expect_an_error("semicolon", "options { catalog-zones { zone \"c.test\" } };", "");
    expect_an_error("view bad", "view v { match-clients { any; }; catalog-zones { zone \"c.test\" default-primaries { 192.0.2.1; } default-masters { 192.0.2.1; }; }; };",
                    "view 'v'|can not be both defined");
}

/* update-policy: grammar from BIND 9.20.4 lib/isccfg/namedconf.c (grant_fields, matchtype_enums), evaluation from lib/dns/ssu.c
 * dns_ssutable_checkrules(): the first rule that matches decides; the identity is the signer's name or *.suffix (a proper subdomain); no rrtype list
 * is every type but NS, SOA and RRSIG; ANY in the list is every type. */
static void test_bind_option_values_update_policy(void) {
    server_config_t cfg;
    if (ok_with("rules",
                "zone \"up.test\" { type master; file \"u\"; update-policy {\n"
                "  deny k1 name bad.up.test. A;\n"
                "  grant k1 zonesub A AAAA;\n"
                "  grant *.dyn.test. self x A;\n"
                "  grant host.up.test. name www.up.test. ANY;\n"
                "  grant k2 selfsub k2 CNAME;\n"
                "  grant k3 selfwild k3 TXT;\n"
                "  grant k5 wildcard *.w.up.test. TXT;\n"
                "  grant k6 subdomain sub.up.test.;\n"
                "  grant k7 krb5-self k7 A;\n"
                "}; };\n", "update-policy: grant krb5-self is not supported", &cfg)) {
        const update_policy_t *p = zext(first_zone(&cfg))->upd_policy;
        CHECK(p && p->count == 8);                              /* the krb5-self grant is dropped */
        CHECK(p && p->rules[1].mtype == UPD_SUBDOMAIN && strcmp(p->rules[1].name, "up.test.") == 0);   /* zonesub: the zone */
        CHECK(p && !update_policy_allows(p, "k1", "bad.up.test.", 1));                     /* the deny comes first */
        CHECK(p && update_policy_allows(p, "k1", "bad.up.test.", 28));                     /* ... only for A */
        CHECK(p && update_policy_allows(p, "k1", "www.up.test.", 1) && update_policy_allows(p, "K1.", "www.up.test.", 28));
        CHECK(p && !update_policy_allows(p, "k1", "www.up.test.", 16) && !update_policy_allows(p, "k1", "www.up.test.", 15));   /* not in the list */
        CHECK(p && !update_policy_allows(p, "k1", "www.other.test.", 1));                  /* outside the zone */
        CHECK(p && !update_policy_allows(p, NULL, "www.up.test.", 1) && !update_policy_allows(NULL, "k1", "www.up.test.", 1));
        CHECK(p && !update_policy_allows(p, "k1", NULL, 1));
        CHECK(p && update_policy_allows(p, "h1.dyn.test.", "h1.dyn.test.", 1));            /* *.suffix identity, self */
        CHECK(p && !update_policy_allows(p, "h1.dyn.test.", "h2.dyn.test.", 1) && !update_policy_allows(p, "dyn.test.", "dyn.test.", 1));
        CHECK(p && update_policy_allows(p, "host.up.test.", "www.up.test.", 2));          /* ANY includes NS */
        CHECK(p && !update_policy_allows(p, "host.up.test.", "mail.up.test.", 1));
        CHECK(p && update_policy_allows(p, "k2", "k2", 5) && update_policy_allows(p, "k2", "a.k2", 5) && !update_policy_allows(p, "k2", "other", 5));
        CHECK(p && update_policy_allows(p, "k3", "a.k3", 16) && !update_policy_allows(p, "k3", "k3", 16));   /* selfwild: a proper subdomain */
        CHECK(p && update_policy_allows(p, "k5", "a.w.up.test.", 16) && !update_policy_allows(p, "k5", "w.up.test.", 16));
        CHECK(p && update_policy_allows(p, "k6", "x.sub.up.test.", 1) && update_policy_allows(p, "k6", "sub.up.test.", 16));
        CHECK(p && !update_policy_allows(p, "k6", "x.sub.up.test.", 2) && !update_policy_allows(p, "k6", "x.sub.up.test.", 6) &&
              !update_policy_allows(p, "k6", "x.sub.up.test.", 46));   /* no type list: not NS, SOA, RRSIG */
        CHECK(p && !update_policy_allows(p, "k6", "up.test.", 1));
        CHECK(p && !update_policy_allows(p, "k7", "k7", 1));       /* the dropped grant allows nothing */
        free_server_config_fields(&cfg);
    }
    /* an empty policy refuses everything; a zone without one has none */
    if (ok_with("empty", "zone \"up.test\" { type master; file \"u\"; update-policy { }; };\nzone \"none.test\" { type master; file \"n\"; };", "", &cfg)) {
        const update_policy_t *p = zext(view_find_zone_config(cfg.views, "up.test"))->upd_policy;
        CHECK(p && p->count == 0 && !update_policy_allows(p, "k", "a.up.test.", 1));
        CHECK(zext(view_find_zone_config(cfg.views, "none.test"))->upd_policy == NULL);
        free_server_config_fields(&cfg);
    }
    /* what KariDNS cannot evaluate: a deny is an error (it would allow what the file forbids), BIND's local needs its session key, a count limit is not enforced */
    expect_an_error("deny tcp-self", "zone \"z.test\" { type master; file \"z\"; update-policy { deny k tcp-self x A; }; };", "update-policy: deny tcp-self cannot be evaluated");
    expect_an_error("local", "zone \"z.test\" { type master; file \"z\"; update-policy local; };", "update-policy local is not supported");
    expect_an_error("count", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k zonesub A(3); }; };", "the count limit of 'A(3)' is not supported");
    expect_an_error("allow-update", "zone \"z.test\" { type master; file \"z\"; allow-update { any; }; update-policy { grant k zonesub ANY; }; };",
                    "zone 'z.test.': 'allow-update' is ignored when 'update-policy' is present");
    expect_an_error("allow-update first", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k zonesub ANY; }; allow-update { key k; }; };", "'allow-update' is ignored when");
    expect_an_error("mode", "zone \"z.test\" { type master; file \"z\"; update-policy { allow k zonesub ANY; }; };", "expected grant or deny, found 'allow'");
    expect_an_error("match type", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k everything x A; }; };", "'everything' is not a match type");
    expect_an_error("record type", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k zonesub NOSUCH; }; };", "'NOSUCH' is not a record type");
    expect_an_error("wildcard name", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k wildcard w.z.test. A; }; };", "a wildcard rule needs a name of the form *.suffix");
    expect_an_error("too many types", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k zonesub A AAAA TXT MX NS SRV PTR CNAME DS TLSA CAA SSHFP NAPTR LOC HINFO RP SPF; }; };",
                    "more than 16 types in one rule");
    {
        char big[4096];
        size_t n = (size_t)snprintf(big, sizeof(big), "zone \"z.test\" { type master; file \"z\"; update-policy {\n");
        for (int i = 0; i < 65; i++) n += (size_t)snprintf(big + n, sizeof(big) - n, "grant k zonesub A;\n");
        snprintf(big + n, sizeof(big) - n, "}; };");
        expect_an_error("too many rules", big, "more than 64 rules");
    }
    expect_an_error("no brace", "zone \"z.test\" { type master; file \"z\"; update-policy grant; };", "");
    expect_an_error("truncated", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k self", "");
    expect_an_error("no semicolon", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k zonesub A } };", "");
    expect_an_error("after rules", "zone \"z.test\" { type master; file \"z\"; update-policy { grant k zonesub A; } };", "");
    {
        char longname[400];
        memset(longname, 'a', 300);
        longname[300] = 0;
        char txt[1200];
        snprintf(txt, sizeof(txt), "zone \"z.test\" { type master; file \"z\"; update-policy { grant %s zonesub A; }; };", longname);
        expect_an_error("identity too long", txt, "the identity is too long");
        snprintf(txt, sizeof(txt), "zone \"z.test\" { type master; file \"z\"; update-policy { grant k name %s A; }; };", longname);
        expect_an_error("name too long", txt, "the name is too long");
    }
    /* the copy of a zone's configuration made for settings received from a primary keeps the policy (zone_ext_clone) */
    if (ok_with("clone", "zone \"c.test\" { type master; file \"c\"; update-policy { grant k zonesub A; }; };", "", &cfg)) {
        char note[200];
        zone_config_t *base = first_zone(&cfg) ? view_find_zone_config(cfg.views, "c.test") : NULL;
        zone_config_t *copy = base ? zone_config_with_received("c.test.", base, NULL, &cfg, note, sizeof(note)) : NULL;
        CHECK(copy && zext(copy)->upd_policy && zext(copy)->upd_policy != zext(base)->upd_policy && zext(copy)->upd_policy->count == 1);
        if (copy) free_zone_config(copy);
        free_server_config_fields(&cfg);
    }
}

int main(void) {
    printf("=== Starting Config Directive Tests ===\n");
    test_bind_option_values_update_policy();
    test_bind_option_values_catalog_zones();
    test_bind_option_values_dnstap();
    test_bind_option_values_aliases();
    test_bind_option_values_tcp();
    test_bind_option_values_minimal_chaos();
    test_bind_option_values_zone();
    test_bind_option_values_limits();
    test_defaults();
    test_boolean_directives();
    test_numeric_directives();
    test_numeric_directives_invalid();
    test_buffer_sizes();
    test_transport_params();
    test_notify_retry();
    test_ixfr_history_option();
    test_xfr_limits_option();
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
    test_refusals_and_limits();
    test_statements_need_a_semicolon();
    test_also_notify_bind();
    test_primaries_and_notify_mode();
    test_strict_options_and_key();
    test_bind_compat_paths();
    test_bind_logging();

    printf("[*] %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("=== Config Directive Tests FAILED ===\n");
        return 1;
    }
    printf("=== All Config Directive Tests PASSED ===\n");
    return 0;
}

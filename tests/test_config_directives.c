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
#include "../dns_utils.h"

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
    };
    static const struct { const char *word; bool value; } words[] = {
        { "yes", true }, { "true", true }, { "no", false }, { "false", false },
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

    if (parse_ok("options { port 5353; tcp-idle-timeout 0; query-log-max-qps 250; "
                 "minimal-any-ttl 300; wire-cache-max-records 12345; };", &cfg)) {
        CHECK(cfg.port == 5353);
        CHECK(cfg.tcp_idle_timeout == 0);
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

static void test_additional_from_auth(void) {
    printf("[TEST] additional-from-auth at options and zone level...\n");
    static const struct { const char *word; additional_from_auth_t expect; } t[] = {
        { "yes", ADDITIONAL_AUTH_YES },        { "true", ADDITIONAL_AUTH_YES },
        { "in-domain", ADDITIONAL_AUTH_IN_DOMAIN }, { "in-zone", ADDITIONAL_AUTH_IN_DOMAIN },
        { "no", ADDITIONAL_AUTH_NO },          { "false", ADDITIONAL_AUTH_NO },
        { "bogus", ADDITIONAL_AUTH_YES },      /* unknown value: warning, falls back to yes */
    };
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
                CHECK(z->additional_from_auth_specified == true);
                CHECK(z->additional_from_auth == t[i].expect);
            }
            free_server_config_fields(&cfg);
        }
    }
    server_config_t cfg;
    if (parse_ok("zone \"example.com\" { type master; file \"z\"; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->additional_from_auth_specified == false);
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
            CHECK(z->ecs_tag_count == 3);
            CHECK(z->location_tag_count == 3);
            if (z->ecs_tag_count == 3) CHECK_STR(z->ecs_tags[0].tag, "eu-tier");
            if (z->location_tag_count == 3) CHECK(z->location_tags[0].cidr_count == 2);
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
        CHECK(z && z->ecs_trusted_resolvers_count == 1);
        CHECK(z && z->ecs_trusted_resolvers_parsed != NULL);
        free_server_config_fields(&cfg);
    }
    expect_reject("options: '{' missing", "options { ecs-trusted-resolvers 192.0.2.1; };");
    expect_reject("options: list unterminated", "options { ecs-trusted-resolvers { 192.0.2.1; ");
    expect_reject("zone: '{' missing",
                  "zone \"example.com\" { type master; file \"z\"; ecs-trusted-resolvers 192.0.2.1; };");
}

/* ------------------------------------------------------------------------ */
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
        CHECK_STR(first_zone(&cfg)->file_format, "bind"); free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; file-format TinyDNS; };", &cfg)) {
        CHECK_STR(first_zone(&cfg)->file_format, "TinyDNS"); free_server_config_fields(&cfg);
    }
    expect_reject("file-format yaml", "zone \"a.test\" { type master; file \"z\"; file-format yaml; };");

    /* catalog-zone, notify-source, file */
    if (parse_ok("zone \"cat.test\" { type master; file \"cat.zone\"; catalog-zone yes; notify-source 192.0.2.10; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->is_catalog == true);
        if (z) { CHECK_STR(z->notify_source, "192.0.2.10"); CHECK_STR(z->file, "cat.zone"); }
        free_server_config_fields(&cfg);
    }
    if (parse_ok("zone \"cat.test\" { type master; file \"cat.zone\"; catalog-zone no; };", &cfg)) {
        CHECK(first_zone(&cfg)->is_catalog == false); free_server_config_fields(&cfg);
    }

    /* masters / also-notify with optional ports */
    if (parse_ok("zone \"s.test\" { type slave; file \"s.zone\"; masters { 192.0.2.1 port 5353; 198.51.100.1; }; "
                 "also-notify { 192.0.2.99 port 5354; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->masters_count == 2 && z->masters_parsed != NULL);
        if (z && z->masters_count == 2) {
            CHECK_STR(z->masters[0].ip, "192.0.2.1"); CHECK(z->masters[0].port == 5353);
            CHECK_STR(z->masters[1].ip, "198.51.100.1"); CHECK(z->masters[1].port == 53);
        }
        CHECK(z && z->also_notify_count == 1 && z->also_notify[0].port == 5354);
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
    if (parse_ok(txt, &cfg)) { CHECK_STR(first_zone(&cfg)->tsig_key, "k1"); free_server_config_fields(&cfg); }
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
            CHECK_STR(z1->program_path, "/usr/local/bin/backend");
            CHECK(z1->program_args_count == 2);
            if (z1->program_args_count == 2) {
                CHECK_STR(z1->program_args[0], "--verbose");
                CHECK_STR(z1->program_args[1], "zone=dyn");
            }
            CHECK_STR(z1->program_user, "svc");
            CHECK(z1->program_timeout_ms == 750);
            CHECK(z1->program_max_failures == 3);
            const zone_config_t *z2 = z1->next;
            CHECK(z2 != NULL);
            if (z2) {
                CHECK_STR(z2->program_path, "/bin/true");
                CHECK_STR(z2->program_user, "nobody");   /* inherited from options { user } */
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
        CHECK(z && z->forwarders_count == 2);
        if (z && z->forwarders_count == 2) {
            CHECK_STR(z->forwarders[0].ip, "192.0.2.53"); CHECK(z->forwarders[0].port == 53);
            CHECK(z->forwarders[1].port == 5353);
        }
        CHECK(z && z->forward_timeout_ms == 1500);
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
            const rate_limit_config_t *r = &z->rrl;
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
        CHECK(z && z->allow_transfer_count == 2);
        if (z && z->allow_transfer_count == 2) {
            CHECK_STR(z->allow_transfer[0], "192.0.2.1");
            CHECK_STR(z->allow_transfer[1], "198.51.100.0/24");
        }
        CHECK(z && z->tsig_keys_count == 1);
        if (z && z->tsig_keys_count == 1) CHECK_STR(z->tsig_keys[0], "k1");
        CHECK(z && z->allow_transfer_parsed != NULL);
        free_server_config_fields(&cfg);
    }
    /* allow-update: a key is kept in the list itself */
    snprintf(txt, sizeof(txt), "%s zone \"a.test\" { type master; file \"z\"; "
             "allow-update { 192.0.2.0/24; key k1; }; };", keydef);
    if (parse_ok(txt, &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->allow_update_count == 2);
        if (z && z->allow_update_count == 2) { CHECK_STR(z->allow_update[0], "192.0.2.0/24"); CHECK_STR(z->allow_update[1], "k1"); }
        free_server_config_fields(&cfg);
    }
    /* single negated entry */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-transfer { ! 192.0.2.9; 192.0.2.0/24; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->allow_transfer_count == 2);
        if (z && z->allow_transfer_count == 2) { CHECK_STR(z->allow_transfer[0], "!192.0.2.9"); CHECK_STR(z->allow_transfer[1], "192.0.2.0/24"); }
        free_server_config_fields(&cfg);
    }
    /* negated block: every member is negated, `any` disappears (BIND: !{ x; any; } == !x) */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-transfer { ! { 10.0.0.0/8; any; }; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->allow_transfer_count == 1);
        if (z && z->allow_transfer_count == 1) CHECK_STR(z->allow_transfer[0], "!10.0.0.0/8");
        free_server_config_fields(&cfg);
    }
    /* double negation inside a negated block cancels: !{ !x; } == x */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-transfer { ! { !192.0.2.1; }; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->allow_transfer_count == 1);
        if (z && z->allow_transfer_count == 1) CHECK_STR(z->allow_transfer[0], "192.0.2.1");
        free_server_config_fields(&cfg);
    }
    /* `any` at top level is an ordinary entry */
    if (parse_ok("zone \"a.test\" { type master; file \"z\"; allow-update { any; }; };", &cfg)) {
        const zone_config_t *z = first_zone(&cfg);
        CHECK(z && z->allow_update_count == 1 && strcmp(z->allow_update[0], "any") == 0);
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

    if (parse_ok("acl \"trusted\" { 192.0.2.0/24; }; statistics-channels { inet 127.0.0.1; };"
                 "options { port 5300; }; " ZONE_MIN, &cfg)) {
        CHECK(cfg.port == 5300);
        CHECK(first_zone(&cfg) != NULL);
        CHECK(cfg.views && strcmp(cfg.views->name, "__default__") == 0);
        CHECK(cfg.zones != NULL && cfg.zones_are_flat == true);
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
    if (parse_ok("zone \"p.com\" { type program; program-command \"/bin/echo\"; file \"z\"; masters { 1.2.3.4; }; }; "
                 "zone \"f.com\" { type forward; forwarders { 1.2.3.4; }; file \"z\"; masters { 1.2.3.4; }; };", &cfg)) {
        free_server_config_fields(&cfg);
    }

    printf("  -> config parser error & warning branches verified.\n");
}

int main(void) {
    printf("=== Starting Config Directive Tests ===\n");
    test_defaults();
    test_boolean_directives();
    test_numeric_directives();
    test_numeric_directives_invalid();
    test_buffer_sizes();
    test_additional_from_auth();
    test_options_syntax_errors();
    test_ecs_and_location_tags();
    test_ecs_trusted_resolvers();
    test_dnstap_block();
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

    printf("[*] %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("=== Config Directive Tests FAILED ===\n");
        return 1;
    }
    printf("=== All Config Directive Tests PASSED ===\n");
    return 0;
}

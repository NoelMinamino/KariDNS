#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include "fi/kari_fi.h"
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_wire.h"
#include "../dns_utils.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static void test_fi_zone_parser(void) {
    const char zone_text[] =
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        "example.com. IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n"
        "example.com. IN NS ns1.example.com.\n"
        "example.com. IN A 192.0.2.1\n"
        "example.com. IN AAAA 2001:db8::1\n"
        "example.com. IN MX 10 mail.example.com.\n"
        "example.com. IN TXT \"hello fault injection\"\n"
        "cname.example.com. IN CNAME example.com.\n"
        "*.wild.example.com. IN A 192.0.2.100\n";

    FI_SWEEP({
        zone_arena_t arena;
        memset(&arena, 0, sizeof(arena));
        zone_arena_init(&arena);

        parse_error_t err = {0};
        parse_context_t ctx = {
            .base_dir = ".",
            .default_origin = "example.com.",
            .is_standalone_mode = true,
            .err_out = &err,
        };

        char buf[sizeof(zone_text)];
        memcpy(buf, zone_text, sizeof(zone_text));
        int rc = parse_zone_fast(buf, sizeof(zone_text) - 1, &arena, &ctx);
        if (rc >= 0) {
            build_zone_index(&arena, true);
        }
        zone_arena_destroy(&arena);
    });
}

static void test_fi_conf_parser(void) {
    const char conf_text[] =
        "options {\n"
        "    directory \"/var/named\";\n"
        "    pid-file \"/var/run/karidns.pid\";\n"
        "    listen-on { 127.0.0.1; };\n"
        "    tcp-idle-timeout 10;\n"
        "    minimal-responses yes;\n"
        "};\n"
        "key \"tsig-key\" {\n"
        "    algorithm hmac-sha256;\n"
        "    secret \"c2VjcmV0MTIzNDU2Nzg5MA==\";\n"
        "};\n"
        "acl \"internal\" {\n"
        "    127.0.0.1;\n"
        "    192.168.0.0/16;\n"
        "};\n"
        "zone \"example.com\" {\n"
        "    type master;\n"
        "    file \"example.com.zone\";\n"
        "    allow-transfer { key \"tsig-key\"; };\n"
        "};\n";

    FI_SWEEP({
        server_config_t config;
        memset(&config, 0, sizeof(config));
        int rc = parse_named_conf(conf_text, &config);
        if (rc == 0) {
            free_server_config_fields(&config);
        }
    });
}

static void test_fi_tinydns_parser(void) {
    const char tinydns_text[] =
        ".example.com:192.0.2.1:a:259200\n"
        "+host1.example.com:192.0.2.2:300\n"
        "3host1.example.com:20010db8000000000000000000000001:300\n"
        "@mail.example.com:192.0.2.3:mail.example.com:10:300\n"
        "'txt.example.com:hello tinydns:300\n"
        "Calias.example.com:host1.example.com:300\n";

    FI_SWEEP({
        zone_arena_t arena;
        memset(&arena, 0, sizeof(arena));
        zone_arena_init(&arena);

        parse_error_t err = {0};
        parse_context_t ctx = {
            .base_dir = ".",
            .default_origin = "example.com.",
            .is_standalone_mode = true,
            .err_out = &err,
        };

        char buf[sizeof(tinydns_text)];
        memcpy(buf, tinydns_text, sizeof(tinydns_text));
        parse_tinydns_data(buf, sizeof(tinydns_text) - 1, &arena, &ctx);
        zone_arena_destroy(&arena);
    });
}

int main(void) {
    printf("[*] Running test_fi_parsers...\n");
    printf("  -> test_fi_zone_parser\n");
    test_fi_zone_parser();
    printf("  -> test_fi_conf_parser\n");
    test_fi_conf_parser();
    printf("  -> test_fi_tinydns_parser\n");
    test_fi_tinydns_parser();
    printf("[+] test_fi_parsers passed successfully.\n");
    return 0;
}

/*
 * pdns_confcheck.h - shared by tests/test_pdns_reader.c and tests/fuzz/fuzz_pdns_metadata.c.
 *
 * The settings text of dns_pdns_reader.c is zone statement syntax of karidns.conf.  Wrapped as
 *     zone "z.test" { type master; file "x"; <text> };
 * the configuration parser must accept whatever the generator emits (the restricted Backend-side parse is B7).
 * The keys the text names must exist for the post-parse checks, so a key block is added for each of them (key names
 * are domain names: "K1" and "k1." are the same key, as in the server's reference check).
 */
#ifndef PDNS_CONFCHECK_H
#define PDNS_CONFCHECK_H

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "../../dns_config_parser.h"

static bool pdns_key_same(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la && a[la - 1] == '.') la--;
    if (lb && b[lb - 1] == '.') lb--;
    return la == lb && strncasecmp(a, b, la) == 0;
}

/* true: parse_named_conf() accepted it and the zone is there.  cfg is filled (free_server_config_fields()). */
static bool pdns_settings_parse(const char *settings, server_config_t *cfg) {
    enum { MAX_KEYS = 64 };
    char names[MAX_KEYS][300];
    size_t nk = 0;
    for (const char *p = settings; (p = strstr(p, "key \"")) != NULL; ) {
        p += 5;
        const char *q = strchr(p, '"');
        if (!q) break;
        char name[300];
        snprintf(name, sizeof(name), "%.*s", (int)(q - p), p);
        bool have = false;
        for (size_t i = 0; i < nk; i++)
            if (pdns_key_same(names[i], name)) have = true;
        if (!have && nk < MAX_KEYS) snprintf(names[nk++], sizeof(names[0]), "%s", name);
        p = q;
    }
    size_t cap = strlen(settings) + nk * 400 + 128;
    char *conf = malloc(cap);
    if (!conf) return false;
    size_t n = 0;
    for (size_t i = 0; i < nk; i++)
        n += (size_t)snprintf(conf + n, cap - n, "key \"%s\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0c2VjcmV0\"; };\n", names[i]);
    snprintf(conf + n, cap - n, "zone \"z.test\" { type master; file \"x\"; %s };\n", settings);
    memset(cfg, 0, sizeof(*cfg));
    int rc = parse_named_conf(conf, cfg);
    free(conf);
    return rc == 0 && config_find_zone_any_view(cfg, "z.test.") != NULL;
}

#endif

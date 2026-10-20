/*
 * fuzz_pdns_metadata.c - domainmetadata rows -> settings text -> configuration parser (dns_pdns_reader.c).
 *
 * Input: rows separated by 0x1E, fields (kind, content) separated by 0x1F.  The settings text the reader makes of
 * them, wrapped as  zone "z.test" { type master; file "x"; <text> };  must always be accepted by the configuration
 * parser (parse_named_conf), and must contain nothing the metadata did not ask for: no `file`, `type`, `program`,
 * `include` statement and no extra zone block.  A parse failure of generated text is a bug: trap.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>

#include "../../dns_pdns_reader.h"
#include "../db/pdns_confcheck.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

/* defined in dns_server_core.c / dns_priv_sandbox.c in the server */
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)path; (void)flags; (void)mode; (void)writable;
    return -1;
}

#define MAX_ROWS 128

static bool has_word(const char *text, const char *w) {
    size_t wl = strlen(w);
    for (const char *p = text; (p = strstr(p, w)) != NULL; p += wl) {
        bool start = p == text || p[-1] == ' ' || p[-1] == ';';
        char after = p[wl];
        if (start && (after == ' ' || after == ';' || after == '\0')) return true;
    }
    return false;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > (1u << 16)) return 0;
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    pdns_zone_t *z = pdns_zone_new("z.test", NULL);
    if (!z) {
        free(buf);
        return 0;
    }
    db_record_row_t soa;
    memset(&soa, 0, sizeof(soa));
    soa.id = 1; soa.ttl = 3600;
    soa.name = "z.test"; soa.type = "SOA";
    soa.content = "ns.z.test hostmaster.z.test 1 7200 3600 1209600 300";
    pdns_zone_add_record(z, &soa);

    size_t pos = 0, nrows = 0;
    while (pos <= size && nrows < MAX_ROWS) {
        char *row = buf + pos;
        size_t rend = pos;
        while (rend < size && (uint8_t)buf[rend] != 0x1E) rend++;
        buf[rend] = '\0';
        char *kind = row, *content = (char *)"";
        char *q = row;
        while (*q && (uint8_t)*q != 0x1F) q++;
        if ((uint8_t)*q == 0x1F) {
            *q = '\0';
            content = q + 1;
            for (char *r = content; *r; r++)
                if ((uint8_t)*r == 0x1F) *r = ' ';
        }
        db_meta_row_t m = { 1, kind, content };
        pdns_zone_add_meta(z, &m);
        nrows++;
        pos = rend + 1;
    }
    if (pdns_zone_finish(z) == 0) {
        const char *s = z->settings;
        if (!s || strlen(s) > PDNS_MAX_SETTINGS) __builtin_trap();
        server_config_t cfg;
        if (!pdns_settings_parse(s, &cfg)) __builtin_trap();
        const zone_config_t *zc = config_find_zone_any_view(&cfg, "z.test.");
        const zone_ext_t *x = zext(zc);
        if (has_word(s, "allow-transfer") && x->allow_transfer_count + x->tsig_keys_count < 1) __builtin_trap();
        if (has_word(s, "allow-update") && x->allow_update_count < 1) __builtin_trap();
        if (has_word(s, "also-notify") && x->also_notify_count < 1) __builtin_trap();
        /* nothing that was not asked for */
        static const char *const forbidden[] = { "file", "type", "program", "program-args", "program-user", "include", "zone",
                                                 "forwarders", "masters", "view", "options" };
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
            if (has_word(s, forbidden[i])) __builtin_trap();
        if (strcmp(zc->type, "master") != 0 || strcmp(zc->file, "x") != 0) __builtin_trap();
        free_server_config_fields(&cfg);
    }
    pdns_zone_free(z);
    free(buf);
    return 0;
}

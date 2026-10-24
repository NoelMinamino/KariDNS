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
#include "../../dns_tsig_acl.h"
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

/* B7a: the Backend side.  The text goes through the restricted parse (db_settings_parse); what it accepts is evaluated
 * against a configuration with an acl-ceiling of 192.0.2.0/24 and the key "k", and no client outside that ceiling may be
 * allowed whatever the text says (design 1.3: a hostile loader cannot widen ACLs beyond acl-ceiling). */
static bool in_ceiling(const char *ip, const char *key) {
    return strncmp(ip, "192.0.2.", 8) == 0 || (key && (strcmp(key, "k") == 0 || strcmp(key, "K.") == 0));
}

static void check_restricted(const char *s, size_t len, bool must_accept) {
    static char kname[] = "k";
    static char *ceil_list[1] = { (char *)"192.0.2.0/24" };
    static char *ceil_keys[1] = { kname };
    static tsig_key_t key = { kname, (char *)"hmac-sha256", NULL, { 0 }, 0, 0, NULL };
    static server_config_t cfg;
    if (!cfg.database.enabled) {
        cfg.database.enabled = true;
        cfg.database.acl_ceiling = ceil_list;
        cfg.database.acl_ceiling_count = 1;
        cfg.database.acl_ceiling_parsed = acl_list_parse(ceil_list, 1);
        cfg.database.acl_ceiling_keys = ceil_keys;
        cfg.database.acl_ceiling_keys_count = 1;
        cfg.keys = &key;
    }
    char err[200];
    zone_ext_shared_t *sh = db_settings_parse(s, len, err, sizeof(err));
    if (!sh) {
        if (must_accept) __builtin_trap();        /* the reader wrote it: the Backend must accept it */
        if (!err[0]) __builtin_trap();            /* a refusal says why */
        return;
    }
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = (char *)"z.test.";
    zc.type = (char *)"master";
    zc.ext = &sh->ext;
    zc.ext_shared = true;                         /* (not freed through free_zone_config: the object is unref'd below) */
    if (!sh->ext.db_acl_ceiling) __builtin_trap();
    static const char *const ips[] = { "192.0.2.5", "198.51.100.9", "2001:db8::1", "10.0.0.1", "192.0.2.255" };
    static const char *const keys[] = { NULL, "k", "x", "K." };
    for (size_t i = 0; i < sizeof(ips) / sizeof(ips[0]); i++)
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); j++)
            if (!in_ceiling(ips[i], keys[j]) &&
                (zone_transfer_acl_allows(&cfg, &zc, ips[i], keys[j]) || zone_update_acl_allows(&cfg, &zc, ips[i], keys[j])))
                __builtin_trap();
    cfg.database.acl_ceiling_count = 0;           /* no ceiling: nobody */
    cfg.database.acl_ceiling_keys_count = 0;
    for (size_t i = 0; i < sizeof(ips) / sizeof(ips[0]); i++)
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); j++)
            if (zone_transfer_acl_allows(&cfg, &zc, ips[i], keys[j]) || zone_update_acl_allows(&cfg, &zc, ips[i], keys[j]))
                __builtin_trap();
    cfg.database.acl_ceiling_count = 1;
    cfg.database.acl_ceiling_keys_count = 1;
    (void)db_settings_missing_key(&sh->ext, &cfg);
    zone_ext_shared_unref(sh);
}

static bool has_word(const char *text, const char *w) {
    size_t wl = strlen(w);
    for (const char *p = text; (p = strstr(p, w)) != NULL; p += wl) {
        bool start = p == text || p[-1] == ' ' || p[-1] == ';';
        char after = p[wl];
        if (start && (after == ' ' || after == ';' || after == '\0')) return true;
    }
    return false;
}

/* the rows of the input into a zone (the buffer is modified: separators become NUL) */
static void feed_rows(pdns_zone_t *z, char *buf, size_t size) {
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
}

/* B7b: a SLAVE / CONSUMER zone made of the same rows, with the content of the first row as domains.master (hostile text).
 * When it converts, the Backend's restricted parse must take its settings and find at least one master. */
static void check_secondary(const uint8_t *data, size_t size) {
    char *buf = malloc(size + 1);
    if (!buf) return;
    memcpy(buf, data, size);
    buf[size] = '\0';
    char *master = buf;
    for (char *q = buf; *q; q++)
        if ((uint8_t)*q == 0x1F) { master = q + 1; break; }
    for (char *q = master; *q; q++)
        if ((uint8_t)*q == 0x1E) { *q = '\0'; break; }
    char *mcopy = strdup(master);
    memcpy(buf, data, size);                      /* feed_rows() needs the separators */
    buf[size] = '\0';
    pdns_zone_t *z = pdns_zone_new("z.test", NULL);
    if (z && mcopy && pdns_zone_set_secondary(z, (size & 1) ? KDB_ZK_SECONDARY : KDB_ZK_CATALOG, mcopy) == 0) {
        feed_rows(z, buf, size);
        if (pdns_zone_finish(z) == 0) {
            const char *s = z->settings;
            if (!s || strlen(s) > PDNS_MAX_SETTINGS || !has_word(s, "masters")) __builtin_trap();
            char err[200];
            zone_ext_shared_t *sh = db_settings_parse(s, strlen(s), err, sizeof(err));
            if (!sh || sh->ext.masters_count < 1 || sh->ext.masters_count > 32) __builtin_trap();
            zone_ext_shared_unref(sh);
            check_restricted(s, strlen(s), true);
        }
    }
    pdns_zone_free(z);
    free(mcopy);
    free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > (1u << 16)) return 0;
    char *buf = malloc(size + 1);
    char *raw = malloc(size + 1);
    if (!buf || !raw) {
        free(buf);
        free(raw);
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';
    memcpy(raw, data, size);
    raw[size] = '\0';
    check_restricted(raw, size, false);           /* the raw input as hostile settings text */
    free(raw);

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

    feed_rows(z, buf, size);
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
        check_restricted(s, strlen(s), true);     /* B7a: and the Backend's restricted parse must take it too */
    }
    pdns_zone_free(z);
    free(buf);
    check_secondary(data, size);
    return 0;
}

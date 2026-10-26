/*
 * fuzz_db_checkline.c - the lines `karidns-dbloader --check` writes, as `karicheck db` reads them (B12, dns_db_checkproto.h).
 *
 * karicheck may be run by root and reads the lines from a process that runs with the rights of loader-user, so every byte of every line
 * is hostile.  The input is cut into lines at 0x0A (at most 64 lines of at most 8 KiB, the fuzzer's own limit); each line goes to the
 * line handler of karicheck (kc_db_line: field split, strict unescape, the Z / S / finding handlers with a configuration that has views,
 * a key, an acl-ceiling and zones of karidns.conf).  Nothing may crash, overflow or hang; the output is thrown away.  The first input
 * byte chooses whether the output is limited to one view (karicheck db VIEW).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define main karicheck_main
#include "../../tools/karicheck.c"
#undef main

/* the findings go nowhere (libFuzzer's own messages use stderr, which must stay open) */
static void null_sink(void *ud, char level, const char *text) {
    (void)ud;
    (void)level;
    (void)text;
}

static server_config_t g_cfg;
static kc_dbsrc_t g_src;
static kc_member_t g_mem[3];

static const char *k_conf =
    "options {\n"
    "  database { driver sqlite3; database-file \"/x\"; loader-user \"u\"; acl-ceiling { 192.0.2.0/24; key \"k\"; }; };\n"
    "};\n"
    "key \"k\" { algorithm hmac-sha256; secret \"c2VjcmV0c2VjcmV0\"; };\n"
    "view \"va\" { match-clients { any; }; zone \"d.test\" { type master; file \"/f\"; }; };\n"
    "view \"vb\" { match-clients { any; }; zone \"p.test\" { type program; program \"/p\"; }; zone \"f.test\" { type forward; forwarders { 192.0.2.53; }; }; };\n"
    "view \"vown\" { match-clients { any; }; database-file \"/y\"; };\n";

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    kc_settings_capture = false;                  /* the second parse (a temporary file per refusal) only slows the fuzzer down */
    char *copy = strdup(k_conf);
    if (!copy || parse_named_conf_ext(copy, "fuzz.conf", &g_cfg) != 0) abort();
    free(copy);
    size_t n = 0;
    for (const view_config_t *v = g_cfg.views; v && n < 3; v = v->next) {
        g_mem[n].v = v;
        g_mem[n].shared = v->database_file == NULL;
        n++;
    }
    g_src.source = "/x";
    g_src.mem = g_mem;
    g_src.nmem = n;
    g_src.cmem = n;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;
    kc_dbrun_t r;
    memset(&r, 0, sizeof(r));
    r.cfg = &g_cfg;
    r.src = &g_src;
    r.t.sink = null_sink;
    r.label = "Database file '/x'";
    r.only = (data[0] & 1) ? g_mem[data[0] >> 1 & 1].v : NULL;
    r.vis = !r.only;
    const uint8_t *p = data + 1, *end = data + size;
    for (int lines = 0; p < end && lines < 64; lines++) {
        const uint8_t *e = memchr(p, '\n', (size_t)(end - p));
        size_t len = e ? (size_t)(e - p) : (size_t)(end - p);
        if (len > 8192) len = 8192;
        char *line = malloc(len + 1);
        if (!line) return 0;
        memcpy(line, p, len);
        line[len] = '\0';
        if (strlen(line) == len) kc_db_line(&r, line);                 /* karicheck drops a line with a NUL in it before this */
        free(line);
        p = e ? e + 1 : end;
    }
    return 0;
}

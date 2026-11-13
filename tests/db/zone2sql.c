/*
 * zone2sql.c - zone file -> PowerDNS 5.1 schema rows / SQL (test importer, beta design 8.2).
 *
 *   zone2sql --dialect sqlite3|pgsql [--zone NAME] zonefile...     (SQL on stdout, one transaction per file)
 *
 * The rows are made by dns_zone_rows.c, the SQL text by zone2sql_lib.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zone2sql.h"
#include "../../dns_log.h"
#undef syslog

int main(int argc, char **argv) {
    klog_nosyslog_from_env("zone2sql");   /* 0.7: the shared parsers' syslog(3) lines on stderr only under KARIDNS_NOSYSLOG=1 (tests/lib_proc.sh) */
    z2s_dialect_t dialect = Z2S_SQLITE3;
    const char *apex_override = NULL;
    bool tinydns = false;
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        if (strcmp(argv[i], "--dialect") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "sqlite3") == 0) dialect = Z2S_SQLITE3;
            else if (strcmp(argv[i], "pgsql") == 0) dialect = Z2S_PGSQL;
            else {
                fprintf(stderr, "zone2sql: unknown dialect '%s' (sqlite3 or pgsql)\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "tinydns") == 0) tinydns = true;
            else if (strcmp(argv[i], "bind") == 0) tinydns = false;
            else {
                fprintf(stderr, "zone2sql: unknown format '%s' (bind or tinydns)\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--plain-signed") == 0) {
            zrows_plain_signed = true;
        } else if (strcmp(argv[i], "--zone") == 0 && i + 1 < argc) {
            apex_override = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            goto usage;
        }
    }
    if (i >= argc) {
    usage:
        fprintf(stderr, "usage: zone2sql --dialect sqlite3|pgsql [--format bind|tinydns] [--zone NAME.] [--plain-signed] zonefile...\n"
                        "  Writes SQL for the PowerDNS 5.1 schema (domains + records) to stdout, one transaction per zone.\n"
                        "  $LOCATION / $ECS-SUBNET tags, tag definitions, tinydns time stamps and locations go into the karidns_* tables\n"
                        "  (db/karidns_ext.*.sql must be applied first); --format tinydns reads a tinydns data file (every zone with an SOA).\n"
                        "  A zone that holds NSEC3 or NSEC records is written the way PowerDNS 5.1 stores a presigned zone (PRESIGNED\n"
                        "  metadata, NSEC3PARAM metadata, no NSEC3 / NSEC3PARAM / NSEC rows, ordername, ENT rows);\n"
                        "  --plain-signed writes the DNSSEC records as ordinary rows instead.\n"
                        "  Example: zone2sql --dialect sqlite3 tests/zones/example.com.zone | sqlite3 pdns.db\n");
        return 2;
    }
    int rc = 0;
    for (; i < argc; i++) {
        /* a tinydns data file can hold several zones: one SQL transaction per zone (the apex of every SOA), and a record of a child zone
         * is left out of its parent, as the server loads a data file whose zones are all configured */
        char **names = NULL;
        int nnames = 0;
        char err[400];
        if (tinydns) {
            if (apex_override) {
                names = malloc(sizeof(char *));
                if (!names || !(names[0] = strdup(apex_override))) {
                    fprintf(stderr, "zone2sql: out of memory\n");
                    return 1;
                }
                nnames = 1;
            } else if (!zrows_tinydns_apexes(argv[i], &names, &nnames, err, sizeof(err))) {
                fprintf(stderr, "zone2sql: %s\n", err);
                rc = 1;
                continue;
            }
        }
        for (int zi = 0; zi < (tinydns ? nnames : 1); zi++) {
            zone_arena_t arena;
            char apex[DNS_NAME_TEXT_SIZE];
            bool ok = tinydns ? zrows_load_tinydns_file(argv[i], names[zi], (const char *const *)names, nnames, &arena, apex, sizeof(apex), err,
                                                      sizeof(err))
                              : zrows_load_zone_file(argv[i], apex_override, &arena, apex, sizeof(apex), err, sizeof(err));
            if (!ok) {
                fprintf(stderr, "zone2sql: %s\n", err);
                rc = 1;
                continue;
            }
            zrows_t rows;
            if (!zrows_from_arena(&arena, apex, &rows, err, sizeof(err))) {
                fprintf(stderr, "zone2sql: %s: %s\n", argv[i], err);
                zone_arena_destroy(&arena);
                rc = 1;
                continue;
            }
            z2s_print_sql(stdout, dialect, &rows);
            zrows_free(&rows);
            zone_arena_destroy(&arena);
        }
        for (int zi = 0; zi < nnames; zi++) free(names[zi]);
        free(names);
    }
    return rc;
}

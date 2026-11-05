/* zone2sql_lib.c - the SQL text of zone2sql (tests/db/zone2sql.h): rows of dns_zone_rows.c -> INSERTs for SQLite3 or PostgreSQL */
#include <stdio.h>
#include "zone2sql.h"

/* ------------------------------------------------------------------------------------------------------------- */
/* SQL                                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static void sql_str(FILE *fp, const char *s) {
    fputc('\'', fp);
    for (; *s; s++) {
        if (*s == '\'') fputc('\'', fp);
        fputc(*s, fp);
    }
    fputc('\'', fp);
}

static void sql_val(FILE *fp, const char *s) {
    if (s) sql_str(fp, s);
    else fputs("NULL", fp);
}

void z2s_print_sql(FILE *fp, z2s_dialect_t d, const zrows_t *r) {
    const char *f = d == Z2S_PGSQL ? "false" : "0";
    const char *t = d == Z2S_PGSQL ? "true" : "1";
    if (d == Z2S_PGSQL) fputs("SET standard_conforming_strings = on;\n", fp);
    fputs("BEGIN;\n", fp);
    fputs("INSERT INTO domains (name, type) VALUES (", fp);
    sql_str(fp, r->zone);
    fputs(", 'NATIVE');\n", fp);
    for (size_t i = 0; i < r->n; i++) {
        const db_record_row_t *row = &r->rows[i];
        fputs("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth, ordername) VALUES "
              "((SELECT id FROM domains WHERE name = ",
              fp);
        sql_str(fp, r->zone);
        fputs("), ", fp);
        sql_str(fp, row->name);
        fputs(", ", fp);
        sql_val(fp, row->type);
        fputs(", ", fp);
        sql_val(fp, row->content);
        fputs(", ", fp);
        if (row->ttl_null) fputs("NULL", fp);
        else fprintf(fp, "%lld", (long long)row->ttl);
        fputs(", ", fp);
        if (row->prio_null) fputs("NULL", fp);
        else fprintf(fp, "%lld", (long long)row->prio);
        fprintf(fp, ", %s, %s, ", f, (!r->auth || r->auth[i]) ? t : f);
        sql_val(fp, row->ordername);
        fputs(");\n", fp);
        const char *last = d == Z2S_PGSQL ? "currval(pg_get_serial_sequence('records', 'id'))" : "last_insert_rowid()";
        if (r->tags && (r->tags[i].loc || r->tags[i].ecs)) {                    /* B8: the row just inserted */
            fprintf(fp, "INSERT INTO karidns_record_tags (record_id, location_tag, ecs_tag) VALUES (%s, ", last);
            sql_val(fp, r->tags[i].loc);
            fputs(", ", fp);
            sql_val(fp, r->tags[i].ecs);
            fputs(");\n", fp);
        }
        if (r->td && r->td[i].has) {
            fprintf(fp, "INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES (%s, %lld, ", last, (long long)r->td[i].ttd);
            sql_val(fp, r->td[i].loc[0] ? r->td[i].loc : NULL);
            fprintf(fp, ", %s);\n", r->td[i].countdown ? t : f);
        }
    }
    for (size_t i = 0; i < r->ndefs; i++) {                                     /* B8: tag definitions, in definition order */
        fputs("INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES ((SELECT id FROM domains WHERE name = ", fp);
        sql_str(fp, r->zone);
        fprintf(fp, "), '%s', ", r->defs[i].kind);
        sql_str(fp, r->defs[i].tag);
        fputs(", ", fp);
        sql_str(fp, r->defs[i].cidr);
        fputs(");\n", fp);
    }
    if (r->tinydns) {
        fputs("INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = ", fp);
        sql_str(fp, r->zone);
        fputs("), 'X-KARIDNS-FORMAT', 'tinydns');\n", fp);
    }
    if (r->presigned) {
        fputs("INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = ", fp);
        sql_str(fp, r->zone);
        fputs("), 'PRESIGNED', '1');\n", fp);
    }
    if (r->nsec3param) {
        fputs("INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = ", fp);
        sql_str(fp, r->zone);
        fputs("), 'NSEC3PARAM', ", fp);
        sql_str(fp, r->nsec3param);
        fputs(");\n", fp);
    }
    fputs("COMMIT;\n", fp);
}


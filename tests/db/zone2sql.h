#ifndef ZONE2SQL_H
#define ZONE2SQL_H

/*
 * zone2sql - test importer: zone file -> SQL for the PowerDNS 5.1 schema (beta design 8.2).  The rows come from the product code
 * (dns_zone_rows.c, see dns_zone_rows.h for the layout); this is the SQL text for both dialects (zone2sql_lib.c), and zone2sql.c the
 * command line.  The SQL needs the ext tables, which the caller creates first (db/karidns_ext.sqlite3.sql).
 */

#include <stdio.h>
#include "../../dns_zone_rows.h"

typedef enum { Z2S_SQLITE3, Z2S_PGSQL } z2s_dialect_t;
void z2s_print_sql(FILE *fp, z2s_dialect_t d, const zrows_t *r);

#endif

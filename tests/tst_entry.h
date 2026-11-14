#ifndef TST_ENTRY_H
#define TST_ENTRY_H
/* A stand-in zone entry for build_zone_response_cache(): it reads only view_name, domain and source.  An empty
 * view_name (NULL here) looks the zone up across all views, as the former (view, domain) arguments did. */
#include <stdio.h>
#include <string.h>
#include "../dns_server_internal.h"

static inline const zone_db_entry_t *tst_entry(const char *view, const char *domain) {
    static zone_db_entry_t e;
    static char name[256];                     /* (the entry keeps a pointer to its name since 0.7 B2) */
    memset(&e, 0, sizeof(e));
    snprintf(name, sizeof(name), "%s", domain);
    e.domain = name;
    snprintf(e.view_name, sizeof(e.view_name), "%s", view ? view : "");
    return &e;
}

#endif

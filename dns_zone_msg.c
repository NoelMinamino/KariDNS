/*
 * dns_zone_msg.c - where the messages of the ZoneImporter and the ZoneExporter go (dns_zone_msg.h).
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "dns_zone_msg.h"

void zmsg_emit(const zmsg_t *m, int sev, dns_diag_code_t code, const char *file, const char *fmt, ...) {
    char text[DIAG_TEXT_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    size_t n = strlen(text);
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r')) text[--n] = '\0';
    if (m && m->fn) m->fn(m->ud, sev, code, file, text);
    else if (sev == ZMSG_DETAIL) dns_diag_detail("%s\n", text);
    else dns_diag(sev, code, file, 0, "%s\n", text);
}

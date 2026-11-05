#ifndef DNS_ZONE_MSG_H
#define DNS_ZONE_MSG_H

/*
 * dns_zone_msg.h - where the messages of the ZoneImporter and the ZoneExporter (dns_zone_import.c, dns_zone_export.c) go.
 *
 * By default through dns_diag() (dns_diag.h): the "[ERROR] ..." lines of the command line tool, or the JSON document with --json, every
 * message with its code (dns_diag_codes.h).  A caller (a test, a program that embeds the library) can take the messages itself with a
 * zmsg_t.  Ordinary process code (malloc allowed); the server does not link it.
 */

#include <stddef.h>
#include "dns_diag.h"

#define ZMSG_DETAIL (-1)        /* sev of a continuation line of the message before it (code DC_NONE) */

/* sev: DIAG_ERROR, DIAG_WARNING, DIAG_NOTE, DIAG_INFO or ZMSG_DETAIL; file: what the message is about (a path, "standard input", NULL); text: one
 * message, without the final line feed. */
typedef void (*zmsg_fn)(void *ud, int sev, dns_diag_code_t code, const char *file, const char *text);

typedef struct {
    zmsg_fn fn;                 /* NULL: dns_diag() / dns_diag_detail() */
    void *ud;
} zmsg_t;

/* m may be NULL (dns_diag).  The text is cut at 4 KiB. */
void zmsg_emit(const zmsg_t *m, int sev, dns_diag_code_t code, const char *file, const char *fmt, ...) __attribute__((format(printf, 5, 6)));

#endif

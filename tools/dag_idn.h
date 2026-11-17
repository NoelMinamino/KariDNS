#ifndef DAG_IDN_H
#define DAG_IDN_H

#include <stdbool.h>

/* The conversion of a name to A-labels that dig 9.20 does for +idnin, shared by dag (idn_to_ascii) and karidns-zone (idn --json).
 * Only with libidn2 (HAVE_LIBIDN2); the server does not link it. */
#ifdef HAVE_LIBIDN2
/* IDNA2008 with the UTS #46 non-transitional mapping; when the first problem is IDN2_DISALLOWED (RFC 5892), the whole name again with the
 * transitional mapping (UTS #46 section 4.1).  locale: read the input as the locale's character set, not as UTF-8.
 * Returns the libidn2 code of the last attempt (IDN2_OK and *out, to be freed with idn2_free()); *first_rc (may be NULL) is the code of the
 * non-transitional attempt; *transitional (may be NULL) is true when the transitional mapping made *out. */
int dag_idn_lookup(const char *name, bool locale, char **out, int *first_rc, bool *transitional);
#endif

#endif

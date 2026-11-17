/* dag_idn.c - the name conversion of dig 9.20's +idnin on libidn2 (see dag_idn.h). */
#ifdef HAVE_LIBIDN2
#include <idn2.h>
#include <stddef.h>
#include <stdint.h>

#include "dag_idn.h"

/* Measured on the build host with dig 9.20.30 / libidn2 2.3.8: ☃.example -> xn--n3h.example, straße.☃.example -> strasse.xn--n3h.example, and
 * a١.☃.example is left alone because its BIDI problem comes first. */
int dag_idn_lookup(const char *name, bool locale, char **out, int *first_rc, bool *transitional) {
    if (transitional) *transitional = false;
    *out = NULL;
    int rc = locale ? idn2_lookup_ul(name, out, IDN2_NONTRANSITIONAL) : idn2_lookup_u8((const uint8_t *)name, (uint8_t **)out, IDN2_NONTRANSITIONAL);
    if (first_rc) *first_rc = rc;
    if (rc == IDN2_DISALLOWED) {
        rc = locale ? idn2_lookup_ul(name, out, IDN2_TRANSITIONAL) : idn2_lookup_u8((const uint8_t *)name, (uint8_t **)out, IDN2_TRANSITIONAL);
        if (rc == IDN2_OK && transitional) *transitional = true;
    }
    return rc;
}
#endif

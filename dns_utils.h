#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "0.2.1"
#endif

#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdatomic.h>
extern _Atomic bool g_capsicum_enabled;

bool split_path_for_openat(const char *path, char *dir_out,
                          size_t dir_out_sz, char *base_out,
                          size_t base_out_sz);

uint16_t get_type_code(const char *type_str);
char *get_base_dir(const char *path);
const char *format_type_name(uint16_t type, char *buf, size_t buf_size);
const char *dns_type_to_string(uint16_t type_code);


int hex_char_to_val(char c);

/* Returns the number of decoded bytes written to `out`, or (size_t)-1 if
 * `out_cap` would be exceeded. Callers MUST check for both 0 (empty/invalid
 * input) AND (size_t)-1 (overflow) — do not assume 0 is the only error value. */
size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap);
int compare_canonical_name(const char *name1, const char *name2);
bool serial_is_newer(uint32_t s1, uint32_t s2);

static inline bool domain_names_match_ci(const char *a, const char *b) {
    if (!a || !b) return false;
    if (strcasecmp(a, b) == 0) return true;
    size_t la = strlen(a);
    size_t lb = strlen(b);
    if (la == lb + 1 && a[la - 1] == '.' && strncasecmp(a, b, lb) == 0) return true;
    if (lb == la + 1 && b[lb - 1] == '.' && strncasecmp(a, b, la) == 0) return true;
    return false;
}

#endif

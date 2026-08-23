#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "0.0.3"
#endif

uint16_t get_type_code(const char *type_str);
char *get_base_dir(const char *path);
const char *format_type_name(uint16_t type, char *buf, size_t buf_size);


int hex_char_to_val(char c);
size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap);
int compare_canonical_name(const char *name1, const char *name2);
bool serial_is_newer(uint32_t s1, uint32_t s2);

#endif

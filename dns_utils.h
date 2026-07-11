#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint16_t get_type_code(const char *type_str);
char *get_base_dir(const char *path);

#endif

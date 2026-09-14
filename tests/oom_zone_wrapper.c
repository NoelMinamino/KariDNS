#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "dns_server_internal.h"

void *calloc(size_t nmemb, size_t size) {
    static void *(*real_calloc)(size_t, size_t) = NULL;
    if (!real_calloc) {
        real_calloc = dlsym(RTLD_NEXT, "calloc");
    }

    size_t total = nmemb * size;
    if (total == sizeof(zone_db_entry_t)) {
        static int zone_calloc_count = 0;
        char *env_n = getenv("OOM_FAIL_NTH_ZONE_CALLOC");
        if (env_n) {
            int target_n = atoi(env_n);
            if (zone_calloc_count == target_n) {
                fprintf(stderr, "[LD_PRELOAD] Intercepted calloc for zone_db_entry_t (call #%d, size=%zu)! Simulating OOM.\n",
                        zone_calloc_count, total);
                zone_calloc_count++;
                return NULL;
            }
        }
        zone_calloc_count++;
    }

    return real_calloc(nmemb, size);
}

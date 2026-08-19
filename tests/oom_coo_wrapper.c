#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

void *realloc(void *ptr, size_t size) {
    static void *(*real_realloc)(void *, size_t) = NULL;
    if (!real_realloc) {
        real_realloc = dlsym(RTLD_NEXT, "realloc");
    }

    if (size == 12288) {
        static int match_count = 0;
        char *env_n = getenv("OOM_FAIL_AFTER_NTH_MATCHING_CALL");
        int target_n = env_n ? atoi(env_n) : 0;
        
        if (match_count == target_n) {
            fprintf(stderr, "[LD_PRELOAD] Intercepted realloc for size=%zu, match=%d! Simulating OOM.\n", size, match_count);
            match_count++;
            return NULL;
        }
        match_count++;
    }

    return real_realloc(ptr, size);
}

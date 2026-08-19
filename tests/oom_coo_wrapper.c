#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// pending_coo_t is 768 bytes.
// We intercept realloc and fail if size is a multiple of 768 and size >= 16 * 768

void *realloc(void *ptr, size_t size) {
    static void *(*real_realloc)(void *, size_t) = NULL;
    if (!real_realloc) {
        real_realloc = dlsym(RTLD_NEXT, "realloc");
    }

    // pending_coo_t size is 3 * 256 = 768 bytes.
    // Capacity starts at 16, so the first realloc is for 16 * 768 = 12288 bytes.
    if (size == 12288 || (size > 0 && size % 768 == 0)) {
        fprintf(stderr, "[LD_PRELOAD] Intercepted realloc for pending_coo_t (size=%zu)! Simulating OOM.\n", size);
        return NULL;
    }

    return real_realloc(ptr, size);
}

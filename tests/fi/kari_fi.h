#ifndef KARI_FI_H
#define KARI_FI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FI_ALLOC = 0,      // malloc, calloc, realloc, strdup, strndup, posix_memalign
    FI_OPEN,           // open, openat, fopen
    FI_READ,           // read, recv
    FI_WRITE,          // write, send, sendto
    FI_SOCKET,         // socket
    FI_BIND,           // bind
    FI_LISTEN,         // listen
    FI_ACCEPT,         // accept
    FI_CONNECT,        // connect
    FI_FCNTL,          // fcntl
    FI_SETSOCKOPT,     // setsockopt
    FI_KEVENT,         // kevent
    FI_RENAME,         // rename
    FI_MKDIR,          // mkdir
    FI_GETADDRINFO,    // getaddrinfo
    FI_PTHREAD_CREATE, // pthread_create
    FI_SSL_CTX_NEW,    // SSL_CTX_new
    FI_SSL_CONNECT,    // SSL_connect
    FI_SSL_READ,       // SSL_read
    FI_SSL_WRITE,      // SSL_write
    FI_KIND_MAX
} fi_kind_t;

void     fi_reset(void);
void     fi_arm_nth(fi_kind_t k, unsigned n);
void     fi_arm_nth_errno(fi_kind_t k, unsigned n, int err_code);
unsigned fi_count(fi_kind_t k);
int      fi_fired(void);
int      fi_fired_kind(fi_kind_t k);
void     fi_pause(void);
void     fi_resume(void);

// Clock injection
void     fi_set_time(time_t fake_time);
void     fi_advance_time(time_t delta_sec);
void     fi_reset_time(void);

// Sweeping macros
#define FI_SWEEP_KIND(kind, ...) do {                                  \
    fi_reset(); do { __VA_ARGS__ } while (0);                          \
    unsigned total_ = fi_count(kind);                                  \
    for (unsigned n_ = 1; n_ <= total_; n_++) {                        \
        fi_reset(); fi_arm_nth(kind, n_);                              \
        do { __VA_ARGS__ } while (0);                                  \
    } } while (0)

#define FI_SWEEP(...) FI_SWEEP_KIND(FI_ALLOC, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // KARI_FI_H

/* dnsqps: the platform glue: the clock, a sleep, the CPUs, Winsock. */
#include "dnsqps.h"
#include <time.h>
#include <pthread.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#endif
#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
#include <pthread_np.h>
#endif
#endif

#ifdef _WIN32
static LARGE_INTEGER g_qpc_freq;

int dq_net_init(void) {
    WSADATA wd;
    QueryPerformanceFrequency(&g_qpc_freq);
    return WSAStartup(MAKEWORD(2, 2), &wd) == 0 ? 0 : -1;
}

uint64_t dq_now_ns(void) {
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((double)c.QuadPart * 1e9 / (double)g_qpc_freq.QuadPart);
}

void dq_sleep_us(unsigned us) { Sleep(us < 1000 ? 1 : us / 1000); }

unsigned dq_ncpus(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
}

int dq_pin_thread(unsigned nth) {
    DWORD_PTR m = ((DWORD_PTR)1) << (nth % (8 * sizeof(DWORD_PTR)));
    return SetThreadAffinityMask(GetCurrentThread(), m) ? 0 : -1;
}
#else
int dq_net_init(void) { return 0; }

uint64_t dq_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void dq_sleep_us(unsigned us) {
    struct timespec ts = { .tv_sec = us / 1000000, .tv_nsec = (long)(us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

#if defined(__linux__)
unsigned dq_ncpus(void) {
    cpu_set_t s;
    if (sched_getaffinity(0, sizeof s, &s) == 0) {
        int n = CPU_COUNT(&s);
        if (n > 0) return (unsigned)n;
    }
    return 1;
}

int dq_pin_thread(unsigned nth) {
    cpu_set_t allowed, one;
    if (sched_getaffinity(0, sizeof allowed, &allowed) != 0) return -1;
    int n = CPU_COUNT(&allowed);
    if (n <= 0) return -1;
    unsigned want = nth % (unsigned)n, seen = 0;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (!CPU_ISSET(i, &allowed)) continue;
        if (seen++ != want) continue;
        CPU_ZERO(&one);
        CPU_SET(i, &one);
        return pthread_setaffinity_np(pthread_self(), sizeof one, &one) == 0 ? 0 : -1;
    }
    return -1;
}
#elif defined(__FreeBSD__)
unsigned dq_ncpus(void) {
    cpuset_t s;
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof s, &s) == 0) {
        unsigned n = 0;
        for (int i = 0; i < CPU_SETSIZE; i++) if (CPU_ISSET(i, &s)) n++;
        if (n) return n;
    }
    return 1;
}

int dq_pin_thread(unsigned nth) {
    cpuset_t allowed, one;
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof allowed, &allowed) != 0) return -1;
    unsigned n = 0;
    for (int i = 0; i < CPU_SETSIZE; i++) if (CPU_ISSET(i, &allowed)) n++;
    if (n == 0) return -1;
    unsigned want = nth % n, seen = 0;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (!CPU_ISSET(i, &allowed)) continue;
        if (seen++ != want) continue;
        CPU_ZERO(&one);
        CPU_SET(i, &one);
        return pthread_setaffinity_np(pthread_self(), sizeof one, &one) == 0 ? 0 : -1;
    }
    return -1;
}
#else
unsigned dq_ncpus(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (unsigned)n : 1;
}

int dq_pin_thread(unsigned nth) {   /* macOS has no thread affinity */
    (void)nth;
    return -1;
}
#endif
#endif

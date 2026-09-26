/*
 * sweep_watchdog.h - hang watchdog for the long-running coverage sweep tests.
 *
 * A sweep that stops making progress (e.g. waiting on a network peer that
 * never answers in a CI VM) would otherwise hang the whole CI job until it
 * is cancelled. wd_start() makes stdout line-buffered, so progress reaches
 * the CI log as it happens, and arms an alarm; if it fires, the test prints
 * the phase it was in and exits with 124. SWEEP_WATCHDOG=<seconds> overrides
 * the limit (0 disables it). Forked children must call wd_child() so that
 * their own alarm() keeps its default meaning.
 */
#ifndef SWEEP_WATCHDOG_H
#define SWEEP_WATCHDOG_H

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *volatile g_wd_name = "sweep";
static const char *volatile g_wd_phase = "startup";

__attribute__((unused)) static void wd_handler(int sig) {
    (void)sig;
    const char *parts[] = { "\n!! watchdog: ", g_wd_name, " made no progress in time; phase: ", g_wd_phase, "\n" };
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
        if (parts[i]) (void)!write(2, parts[i], strlen(parts[i]));
    _exit(124);
}

__attribute__((unused)) static void wd_start(const char *name, unsigned seconds) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_wd_name = name;
    const char *e = getenv("SWEEP_WATCHDOG");
    if (e) seconds = (unsigned)strtoul(e, NULL, 10);
    if (seconds == 0) return;
    signal(SIGALRM, wd_handler);
    alarm(seconds);
}

#define WD_PHASE(p) (g_wd_phase = (p))

__attribute__((unused)) static void wd_child(void) {
    signal(SIGALRM, SIG_DFL);
}

#endif /* SWEEP_WATCHDOG_H */

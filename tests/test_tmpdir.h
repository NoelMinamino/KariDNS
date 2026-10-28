/*
 * test_tmpdir.h - remove a test's mkdtemp() directory once the test has passed.
 *
 * nftw() instead of system("rm -rf"): fork() from a multi-threaded test process can deadlock the child under ASan on FreeBSD.
 * A failing test returns before the call, so its directory is left for inspection.
 */
#ifndef TEST_TMPDIR_H
#define TEST_TMPDIR_H

#include <ftw.h>
#include <stdio.h>
#include <sys/stat.h>

__attribute__((unused)) static int tmpdir_rm_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb; (void)type; (void)ftw;
    return remove(path);
}

/* An empty name (the directory was never made) is ignored; a failure only leaves files behind. */
__attribute__((unused)) static void tmpdir_remove(const char *dir) {
    if (!dir || !dir[0]) return;
    if (nftw(dir, tmpdir_rm_entry, 16, FTW_DEPTH | FTW_PHYS) != 0) fprintf(stderr, "[i] could not remove %s\n", dir);
}

#endif

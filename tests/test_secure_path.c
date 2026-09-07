#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <limits.h>

#include "../dns_utils.h"
#include "../dns_config_parser.h"

// Stub for open_via_dir_cache when running unit tests outside full server
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static void test_split_path_for_openat(void) {
    printf("[Test 1] split_path_for_openat...\n");
    char dir[PATH_MAX];
    char base[PATH_MAX];

    // Standard nested path
    assert(split_path_for_openat("/home/user/work/my_dns/tests/zones/example.com.zone", dir, sizeof(dir), base, sizeof(base)));
    assert(strcmp(dir, "/home/user/work/my_dns/tests/zones") == 0);
    assert(strcmp(base, "example.com.zone") == 0);

    // Root-level path
    assert(split_path_for_openat("/root.zone", dir, sizeof(dir), base, sizeof(base)));
    assert(strcmp(dir, "/") == 0);
    assert(strcmp(base, "root.zone") == 0);

    // Basename only
    assert(split_path_for_openat("test.conf", dir, sizeof(dir), base, sizeof(base)));
    assert(strcmp(dir, ".") == 0);
    assert(strcmp(base, "test.conf") == 0);

    // Invalid base components (security checks)
    assert(!split_path_for_openat("/a/b/..", dir, sizeof(dir), base, sizeof(base)));
    assert(!split_path_for_openat("/a/b/.", dir, sizeof(dir), base, sizeof(base)));
    assert(!split_path_for_openat("", dir, sizeof(dir), base, sizeof(base)));
    assert(!split_path_for_openat(NULL, dir, sizeof(dir), base, sizeof(base)));

    printf("  -> PASS\n");
}

static void test_is_path_safe_under_cwd_standard(void) {
    printf("[Test 2] is_path_safe_under_cwd (Standard Mode)...\n");
    char resolved[PATH_MAX];

    // 1. Valid file inside workspace
    assert(is_path_safe_under_cwd("tests/zones/example.com.zone", resolved, sizeof(resolved)));
    assert(strstr(resolved, "tests/zones/example.com.zone") != NULL);

    // 2. Valid relative path with ../ staying within workspace
    assert(is_path_safe_under_cwd("tests/../tests/zones/example.com.zone", resolved, sizeof(resolved)));
    assert(strstr(resolved, "tests/zones/example.com.zone") != NULL);
    assert(strstr(resolved, "..") == NULL); // Must be normalized

    // 3. Path traversal attempting to escape workspace
    assert(!is_path_safe_under_cwd("../../../../../../../../etc/passwd", resolved, sizeof(resolved)));
    assert(!is_path_safe_under_cwd("../../../../../../../../etc/shadow", resolved, sizeof(resolved)));

    // 4. Forbidden system paths
    assert(!is_path_safe_under_cwd("/etc/passwd", resolved, sizeof(resolved)));
    assert(!is_path_safe_under_cwd("/etc/shadow", resolved, sizeof(resolved)));
    assert(!is_path_safe_under_cwd("/proc/cpuinfo", resolved, sizeof(resolved)));
    assert(!is_path_safe_under_cwd("/sys/kernel", resolved, sizeof(resolved)));

    // 5. Symlink inside workspace (should be allowed, and output must preserve logical normalized path)
#ifndef _WIN32
    mkdir("tests_symlink_tmp", 0755);
    mkdir("tests_symlink_tmp/dir1", 0755);
    FILE *f = fopen("tests_symlink_tmp/dir1/test.txt", "w");
    if (f) { fprintf(f, "hello\n"); fclose(f); }
    unlink("tests_symlink_tmp/dir2");
    symlink("dir1", "tests_symlink_tmp/dir2");

    assert(is_path_safe_under_cwd("tests_symlink_tmp/dir2/test.txt", resolved, sizeof(resolved)));
    // Must preserve dir2 in logical path so directory FD cache keys match!
    assert(strstr(resolved, "tests_symlink_tmp/dir2/test.txt") != NULL);

    // 6. Symlink escaping workspace (must be rejected!)
    unlink("tests_symlink_tmp/esc_etc");
    symlink("/etc", "tests_symlink_tmp/esc_etc");
    assert(!is_path_safe_under_cwd("tests_symlink_tmp/esc_etc/passwd", resolved, sizeof(resolved)));

    unlink("tests_symlink_tmp/esc_etc");
    unlink("tests_symlink_tmp/dir2");
    unlink("tests_symlink_tmp/dir1/test.txt");
    rmdir("tests_symlink_tmp/dir1");
    rmdir("tests_symlink_tmp");
#endif

    printf("  -> PASS\n");
}

static void test_is_path_safe_under_cwd_capsicum(void) {
    printf("[Test 3] is_path_safe_under_cwd (Capsicum Capability Mode)...\n");
    char resolved_std[PATH_MAX];
    char resolved_cap[PATH_MAX];

    // Get standard resolution first
    assert(is_path_safe_under_cwd("tests/zones/example.com.zone", resolved_std, sizeof(resolved_std)));

    // Enable simulated Capsicum mode (no syscalls permitted)
    atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);

    // 1. Valid file inside workspace under Capsicum
    assert(is_path_safe_under_cwd("tests/zones/example.com.zone", resolved_cap, sizeof(resolved_cap)));
    assert(strcmp(resolved_std, resolved_cap) == 0); // Exact match with pre-Capsicum normalized path!

    // 2. Traversal attempt under Capsicum must be rejected by in-memory prefix check
    assert(!is_path_safe_under_cwd("../../../../../../../../etc/passwd", resolved_cap, sizeof(resolved_cap)));
    assert(!is_path_safe_under_cwd("/etc/shadow", resolved_cap, sizeof(resolved_cap)));

    // 3. Directory cache key consistency check:
    // Ensure that split_path_for_openat produces the identical directory path
    // in both standard mode and Capsicum mode.
    char dir_std[PATH_MAX], base_std[PATH_MAX];
    char dir_cap[PATH_MAX], base_cap[PATH_MAX];
    assert(split_path_for_openat(resolved_std, dir_std, sizeof(dir_std), base_std, sizeof(base_std)));
    assert(split_path_for_openat(resolved_cap, dir_cap, sizeof(dir_cap), base_cap, sizeof(base_cap)));
    assert(strcmp(dir_std, dir_cap) == 0);
    assert(strcmp(base_std, base_cap) == 0);

    // Disable Capsicum mode
    atomic_store_explicit(&g_capsicum_enabled, false, memory_order_release);

    printf("  -> PASS\n");
}

static void test_program_user_fallback(void) {
    printf("[Test 4] program-user inheritance in named.conf parsing...\n");

    // Case A: options { user "nobody"; } set, program zone has NO program-user
    // -> Must inherit "nobody"
    {
        const char *conf_src =
            "options {\n"
            "    port 10053;\n"
            "    user \"nobody\";\n"
            "    group \"nobody\";\n"
            "};\n"
            "zone \"anomaly.test.\" {\n"
            "    type program;\n"
            "    program \"/bin/echo\";\n"
            "};\n";

        server_config_t cfg;
        int res = parse_named_conf(conf_src, &cfg);
        assert(res == 0);
        assert(cfg.zones != NULL);
        assert(strcmp(cfg.zones->domain, "anomaly.test.") == 0);
        assert(cfg.zones->program_user != NULL);
        assert(strcmp(cfg.zones->program_user, "nobody") == 0);
        free_server_config_fields(&cfg);
    }

    // Case B: program zone has explicit program-user "daemon"
    // -> Must preserve "daemon"
    {
        const char *conf_src =
            "options {\n"
            "    port 10053;\n"
            "    user \"nobody\";\n"
            "    group \"nobody\";\n"
            "};\n"
            "zone \"anomaly.test.\" {\n"
            "    type program;\n"
            "    program \"/bin/echo\";\n"
            "    program-user \"daemon\";\n"
            "};\n";

        server_config_t cfg;
        int res = parse_named_conf(conf_src, &cfg);
        assert(res == 0);
        assert(cfg.zones != NULL);
        assert(cfg.zones->program_user != NULL);
        assert(strcmp(cfg.zones->program_user, "daemon") == 0);
        free_server_config_fields(&cfg);
    }

    // Case C: neither options.user nor program-user is set
    // -> program_user remains NULL (server will safely reject starting as root)
    {
        const char *conf_src =
            "options {\n"
            "    port 10053;\n"
            "};\n"
            "zone \"anomaly.test.\" {\n"
            "    type program;\n"
            "    program \"/bin/echo\";\n"
            "};\n";

        server_config_t cfg;
        int res = parse_named_conf(conf_src, &cfg);
        assert(res == 0);
        assert(cfg.zones != NULL);
        assert(cfg.zones->program_user == NULL);
        free_server_config_fields(&cfg);
    }

    printf("  -> PASS\n");
}

int main(void) {
    printf("=== Running KariDNS Path Safety & Capsicum Regression Tests ===\n");
    init_workspace_root();

    test_split_path_for_openat();
    test_is_path_safe_under_cwd_standard();
    test_is_path_safe_under_cwd_capsicum();
    test_program_user_fallback();

    printf("\n[ALL TESTS PASSED] Secure path resolution and Capsicum consistency verified!\n");
    return 0;
}

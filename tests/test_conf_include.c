#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../dns_config_parser.h"
#include "../dns_utils.h"

// Stub for open_via_dir_cache when running unit tests outside full server
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static void create_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    if (content && strlen(content) > 0) {
        fwrite(content, 1, strlen(content), f);
    }
    fclose(f);
}

int main(void) {
    printf("=== Running KariDNS Config Include Tests ===\n");

    // Setup temporary test directory structure
    mkdir("tests_inc_tmp", 0755);
    mkdir("tests_inc_tmp/sub", 0755);
    mkdir("tests_inc_tmp/deep", 0755);

    // Test 1: Top-level include
    {
        printf("[Test 1] Top-level include (TSIG key)...\n");
        create_file("tests_inc_tmp/keys.conf",
                    "key \"test-key\" { algorithm \"hmac-sha256\"; secret \"k7e8vW8f0W4v9B+5Y8f0W4v9B+5Y8f0W4v9B+5Y8f0U=\"; };\n");
        create_file("tests_inc_tmp/main_key.conf",
                    "options { port 53; };\n"
                    "include \"keys.conf\";\n"
                    "zone \"example.com\" { type master; file \"example.com.zone\"; };\n");

        char *buf = read_entire_file("tests_inc_tmp/main_key.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/main_key.conf", &cfg);
        free(buf);

        assert(res == 0);
        assert(cfg.keys != NULL);
        assert(strcmp(cfg.keys->name, "test-key") == 0);
        assert(strcmp(cfg.keys->algorithm, "hmac-sha256") == 0);
        assert(cfg.zones != NULL);
        assert(strcmp(cfg.zones->domain, "example.com.") == 0);
        free_server_config_fields(&cfg);
        printf("  -> PASS\n");
    }

    // Test 2: In-block / list-middle include
    {
        printf("[Test 2] In-block and list-middle include (allow-transfer ACL)...\n");
        create_file("tests_inc_tmp/slaves.conf",
                    "192.168.1.1;\n"
                    "192.168.1.2;\n");
        create_file("tests_inc_tmp/main_acl.conf",
                    "zone \"example.com\" {\n"
                    "    type master;\n"
                    "    file \"example.com.zone\";\n"
                    "    allow-transfer {\n"
                    "        10.0.0.1;\n"
                    "        include \"slaves.conf\";\n"
                    "        10.0.0.2;\n"
                    "    };\n"
                    "};\n");

        char *buf = read_entire_file("tests_inc_tmp/main_acl.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/main_acl.conf", &cfg);
        free(buf);

        assert(res == 0);
        assert(cfg.zones != NULL);
        assert(cfg.zones->allow_transfer_count == 4);
        assert(strcmp(cfg.zones->allow_transfer[0], "10.0.0.1") == 0);
        assert(strcmp(cfg.zones->allow_transfer[1], "192.168.1.1") == 0);
        assert(strcmp(cfg.zones->allow_transfer[2], "192.168.1.2") == 0);
        assert(strcmp(cfg.zones->allow_transfer[3], "10.0.0.2") == 0);
        free_server_config_fields(&cfg);
        printf("  -> PASS\n");
    }

    // Test 3: Relative path resolution across subdirectories
    {
        printf("[Test 3] Relative path resolution across subdirectories...\n");
        create_file("tests_inc_tmp/sub/leaf.conf",
                    "key \"sub-key\" { algorithm \"hmac-sha256\"; secret \"k7e8vW8f0W4v9B+5Y8f0W4v9B+5Y8f0W4v9B+5Y8f0U=\"; };\n");
        create_file("tests_inc_tmp/sub/nested.conf",
                    "// include relative to sub directory\n"
                    "include \"leaf.conf\";\n");
        create_file("tests_inc_tmp/main_rel.conf",
                    "include \"sub/nested.conf\";\n");

        char *buf = read_entire_file("tests_inc_tmp/main_rel.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/main_rel.conf", &cfg);
        free(buf);

        assert(res == 0);
        assert(cfg.keys != NULL);
        assert(strcmp(cfg.keys->name, "sub-key") == 0);
        free_server_config_fields(&cfg);
        printf("  -> PASS\n");
    }

    // Test 4: Empty files and comments-only files resilience
    {
        printf("[Test 4] Empty file and comments-only include resilience...\n");
        create_file("tests_inc_tmp/empty.conf", "");
        create_file("tests_inc_tmp/comments_only.conf",
                    "# Only comments here\n"
                    "// Another comment\n"
                    "/* Block comment */\n");
        create_file("tests_inc_tmp/main_empty.conf",
                    "include \"empty.conf\";\n"
                    "zone \"empty-test.org\" {\n"
                    "    type master;\n"
                    "    file \"test.zone\";\n"
                    "    allow-transfer {\n"
                    "        include \"comments_only.conf\";\n"
                    "        127.0.0.1;\n"
                    "        include \"empty.conf\";\n"
                    "    };\n"
                    "};\n"
                    "include \"comments_only.conf\";\n");

        char *buf = read_entire_file("tests_inc_tmp/main_empty.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/main_empty.conf", &cfg);
        free(buf);

        assert(res == 0);
        assert(cfg.zones != NULL);
        assert(strcmp(cfg.zones->domain, "empty-test.org.") == 0);
        assert(cfg.zones->allow_transfer_count == 1);
        assert(strcmp(cfg.zones->allow_transfer[0], "127.0.0.1") == 0);
        free_server_config_fields(&cfg);
        printf("  -> PASS\n");
    }

    // Test 5: Multi-level deep nesting (4 levels)
    {
        printf("[Test 5] Multi-level deep nesting (4 levels)...\n");
        create_file("tests_inc_tmp/deep/l4.conf", "port 5353;\n");
        create_file("tests_inc_tmp/deep/l3.conf", "include \"l4.conf\";\n");
        create_file("tests_inc_tmp/deep/l2.conf", "include \"l3.conf\";\n");
        create_file("tests_inc_tmp/main_deep.conf",
                    "options {\n"
                    "    include \"deep/l2.conf\";\n"
                    "};\n");

        char *buf = read_entire_file("tests_inc_tmp/main_deep.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/main_deep.conf", &cfg);
        free(buf);

        assert(res == 0);
        assert(cfg.port == 5353);
        free_server_config_fields(&cfg);
        printf("  -> PASS\n");
    }

    // Test 6: Direct circular include (self-reference)
    {
        printf("[Test 6] Direct circular include detection...\n");
        create_file("tests_inc_tmp/cyclic_self.conf",
                    "include \"cyclic_self.conf\";\n");

        char *buf = read_entire_file("tests_inc_tmp/cyclic_self.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/cyclic_self.conf", &cfg);
        free(buf);

        assert(res == -1); // Must fail and abort cleanly
        printf("  -> PASS (detected and safely aborted)\n");
    }

    // Test 7: Indirect circular include (A -> B -> A)
    {
        printf("[Test 7] Indirect circular include detection (A -> B -> A)...\n");
        create_file("tests_inc_tmp/cyclic_a.conf",
                    "include \"cyclic_b.conf\";\n");
        create_file("tests_inc_tmp/cyclic_b.conf",
                    "include \"cyclic_a.conf\";\n");

        char *buf = read_entire_file("tests_inc_tmp/cyclic_a.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/cyclic_a.conf", &cfg);
        free(buf);

        assert(res == -1); // Must fail and abort cleanly
        printf("  -> PASS (detected and safely aborted)\n");
    }

    // Test 8: Non-existent file include
    {
        printf("[Test 8] Non-existent include file error handling...\n");
        create_file("tests_inc_tmp/missing_inc.conf",
                    "include \"non_existent_file_never_exists.conf\";\n");

        char *buf = read_entire_file("tests_inc_tmp/missing_inc.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/missing_inc.conf", &cfg);
        free(buf);

        assert(res == -1); // Must fail
        printf("  -> PASS (detected and safely aborted)\n");
    }

    // Test 9: Include depth limit exceeded (> 16)
    {
        printf("[Test 9] Include depth limit exceeded (> 16)...\n");
        for (int i = 0; i < 20; i++) {
            char path[128];
            char content[128];
            snprintf(path, sizeof(path), "tests_inc_tmp/nest_%d.conf", i);
            if (i < 19) {
                snprintf(content, sizeof(content), "include \"nest_%d.conf\";\n", i + 1);
            } else {
                snprintf(content, sizeof(content), "port 53;\n");
            }
            create_file(path, content);
        }

        char *buf = read_entire_file("tests_inc_tmp/nest_0.conf", NULL, NULL);
        assert(buf != NULL);
        server_config_t cfg;
        int res = parse_named_conf_ext(buf, "tests_inc_tmp/nest_0.conf", &cfg);
        free(buf);

        assert(res == -1); // Depth exceeded
        printf("  -> PASS (depth limit enforced)\n");
    }

    // Test 10: Syntax error in include statement (missing semicolon / bad token)
    {
        printf("[Test 10] Syntax error in include directive...\n");
        create_file("tests_inc_tmp/bad_syntax1.conf", "include ;");
        create_file("tests_inc_tmp/bad_syntax2.conf", "include \"keys.conf\"");

        char *buf1 = read_entire_file("tests_inc_tmp/bad_syntax1.conf", NULL, NULL);
        server_config_t cfg1;
        int res1 = parse_named_conf_ext(buf1, "tests_inc_tmp/bad_syntax1.conf", &cfg1);
        free(buf1);
        assert(res1 == -1);

        char *buf2 = read_entire_file("tests_inc_tmp/bad_syntax2.conf", NULL, NULL);
        server_config_t cfg2;
        int res2 = parse_named_conf_ext(buf2, "tests_inc_tmp/bad_syntax2.conf", &cfg2);
        free(buf2);
        assert(res2 == -1);

        printf("  -> PASS (syntax errors caught)\n");
    }

    // Test 11: Literal quoted string "include" (zone domain / key name)
    {
        printf("[Test 11] Literal quoted string \"include\" domain name...\n");
        const char *conf =
            "zone \"include\" {\n"
            "    type master;\n"
            "    file \"include.zone\";\n"
            "};\n";

        server_config_t cfg;
        int res = parse_named_conf(conf, &cfg);
        assert(res == 0);
        assert(cfg.zones != NULL);
        assert(strcmp(cfg.zones->domain, "include.") == 0);
        free_server_config_fields(&cfg);
        printf("  -> PASS (quoted \"include\" preserved as string literal)\n");
    }

    // Clean up temporary test files
    unlink("tests_inc_tmp/keys.conf");
    unlink("tests_inc_tmp/main_key.conf");
    unlink("tests_inc_tmp/slaves.conf");
    unlink("tests_inc_tmp/main_acl.conf");
    unlink("tests_inc_tmp/sub/leaf.conf");
    unlink("tests_inc_tmp/sub/nested.conf");
    unlink("tests_inc_tmp/main_rel.conf");
    unlink("tests_inc_tmp/empty.conf");
    unlink("tests_inc_tmp/comments_only.conf");
    unlink("tests_inc_tmp/main_empty.conf");
    unlink("tests_inc_tmp/deep/l4.conf");
    unlink("tests_inc_tmp/deep/l3.conf");
    unlink("tests_inc_tmp/deep/l2.conf");
    unlink("tests_inc_tmp/main_deep.conf");
    unlink("tests_inc_tmp/cyclic_self.conf");
    unlink("tests_inc_tmp/cyclic_a.conf");
    unlink("tests_inc_tmp/cyclic_b.conf");
    unlink("tests_inc_tmp/missing_inc.conf");
    unlink("tests_inc_tmp/bad_syntax1.conf");
    unlink("tests_inc_tmp/bad_syntax2.conf");
    for (int i = 0; i < 20; i++) {
        char path[128];
        snprintf(path, sizeof(path), "tests_inc_tmp/nest_%d.conf", i);
        unlink(path);
    }
    rmdir("tests_inc_tmp/sub");
    rmdir("tests_inc_tmp/deep");
    rmdir("tests_inc_tmp");

    printf("\n=== ALL CONFIG INCLUDE TESTS PASSED! ===\n");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_utils.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

// Stub for open_via_dir_cache used by dns_config_parser.c
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

// Helper to read entire file
static char *read_file_or_die(const char *path, bool *out_failed) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not open file: %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not read file: %s\n", path);
        return NULL;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Out of memory reading file: %s\n", path);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, len, f);
    buf[read_bytes] = '\0';
    fclose(f);
    if (out_failed) *out_failed = false;
    return buf;
}

static char *karicheck_load_file_cb(parse_context_t *ctx, const char *rel_path) {
    (void)ctx;
    return read_file_or_die(rel_path, NULL);
}


// Print error context with caret
static void print_error_context(const char *root_file_path, const char *root_buf, const parse_error_t *err, zone_arena_t *arena) {
    const char *file_path = root_file_path;
    const char *buf = root_buf;

    if (err->file_path) {
        bool found = false;
        for (int i = 0; i < arena->file_buf_count; i++) {
            if (arena->file_paths[i] && strcmp(arena->file_paths[i], err->file_path) == 0) {
                file_path = err->file_path;
                buf = arena->display_bufs[i];
                found = true;
                break;
            }
        }
        if (!found) {
            file_path = root_file_path;
            buf = root_buf;
        }
    }
    if (!buf) return;
    size_t offset = err->error_offset;
    size_t buf_len = strlen(buf);
    if (offset > buf_len) offset = buf_len;

    int line = 1;
    const char *line_start = buf;
    for (size_t i = 0; i < offset; i++) {
        if (buf[i] == '\n') {
            line++;
            line_start = buf + i + 1;
        }
    }

    const char *line_end = line_start;
    while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;

    fprintf(stderr, "[ERROR] Syntax error in %s at line %d\n", file_path, line);
    fprintf(stderr, "Reason: %s\n\n", err->error_message);

    // Limit line length to 80 chars
    size_t len = line_end - line_start;
    const char *print_start = line_start;
    int caret_pos = offset - (line_start - buf);
    bool clipped_start = false;
    bool clipped_end = false;

    if (len > 80) {
        if (caret_pos > 40) {
            print_start = line_start + caret_pos - 35;
            clipped_start = true;
        }
        if (line_end - print_start > 80) {
            len = 80;
            clipped_end = true;
        } else {
            len = line_end - print_start;
        }
        caret_pos = offset - (print_start - buf);
    }

    fprintf(stderr, "%4d | ", line);
    if (clipped_start) fprintf(stderr, "... ");
    for (size_t i = 0; i < len; i++) {
        char c = print_start[i];
        if (c == '\r' || c == '\n' || c == '\0') break;
        fputc(c, stderr);
    }
    if (clipped_end) fprintf(stderr, " ...");
    fprintf(stderr, "\n");

    fprintf(stderr, "       ");
    if (clipped_start) fprintf(stderr, "    ");
    for (int i = 0; i < caret_pos; i++) fputc(' ', stderr);
    fprintf(stderr, "\033[1;31m^");
    for (size_t i = 1; i < err->token_length && i < 20; i++) fputc('~', stderr);
    fprintf(stderr, "\033[0m\n\n");
}

static int check_zone(const char *domain, const char *file_path, bool is_standalone) {
    if (is_standalone) {
        if (file_path[0] == '/' || strstr(file_path, "../")) {
            fprintf(stderr, "[WARNING] In standalone mode, absolute paths or '../' in $INCLUDE are tested using host filesystem, but will be rejected by KariDNS ECAPMODE sandbox!\n");
        }
    }

    bool failed = false;
    char *buf = read_file_or_die(file_path, &failed);
    if (failed || !buf) return 1;

    char *mutable_buf = strdup(buf);
    if (!mutable_buf) {
        free(buf);
        fprintf(stderr, "[ERROR] Out of memory\n");
        return 1;
    }

    zone_arena_t arena;
    zone_arena_init(&arena);

    arena.file_bufs[0] = mutable_buf;
    arena.display_bufs[0] = (char*)buf;
    arena.file_paths[0] = strdup(file_path);
    arena.file_buf_count = 1;

    parse_error_t err = {0};
    char *root_ttl = NULL;
    char *visited_paths[16];
    char *root_path = realpath(file_path, NULL);
    if (!root_path) root_path = strdup(file_path);

    parse_context_t ctx = {
        .base_dir = get_base_dir(file_path),
        .default_origin = domain,
        .is_standalone_mode = is_standalone,
        .err_out = &err,
        .current_depth = 0,
        .visited_paths = visited_paths,
        .visited_count = 1,
        .visited_cap = 16,
        .load_file_cb = karicheck_load_file_cb,
        .shared_ttl_io = &root_ttl
    };
    ctx.visited_paths[0] = root_path;

    int res = parse_zone_fast(mutable_buf, strlen(mutable_buf), &arena, &ctx);
    if (res < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    if (arena.count == 0) {
        fprintf(stderr, "[ERROR] No records found in zone '%s' (%s)\n", domain, file_path);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    bool has_soa = false;
    for (size_t i = 0; i < arena.count; i++) {
        if (arena.records[i].type_code == 6 && strcasecmp(arena.records[i].name, domain) == 0) {
            has_soa = true;
        }
        if (arena.records[i].type_code == 62) { // CSYNC
            for (int j = 2; j < arena.records[i].rdata_count; j++) {
                if (get_type_code(arena.records[i].rdata[j]) == 0) {
                    fprintf(stderr, "[WARNING] CSYNC record contains unknown type '%s' in zone '%s' (%s)\n", arena.records[i].rdata[j], domain, file_path);
                }
            }
        }
    }

    if (!has_soa) {
        fprintf(stderr, "[ERROR] No SOA record found in zone '%s' (%s) at origin\n", domain, file_path);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    printf("[OK] Zone '%s' is valid.\n", domain);
    free((void*)ctx.base_dir);
    zone_arena_destroy(&arena);
    free(root_path);
    return 0;
}

static int check_config(const char *config_path, server_config_t *cfg) {
    printf("[INFO] Loading config %s...\n", config_path);
    bool failed = false;
    char *buf = read_file_or_die(config_path, &failed);
    if (failed || !buf) return 1;

    if (parse_named_conf(buf, cfg) != 0) {
        fprintf(stderr, "[ERROR] Syntax error in config file: %s\n", config_path);
        free(buf);
        return 1;
    }
    printf("[OK] Config file %s is valid.\n", config_path);
    free(buf);
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s conf [config_path]\n", prog);
    fprintf(stderr, "  %s zones [config_path]\n", prog);
    fprintf(stderr, "  %s zone <domain> [config_path]\n", prog);
    fprintf(stderr, "  %s zone <domain> <zone_file_path>\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *default_config = "/usr/local/etc/karidns.conf";

    if (strcmp(cmd, "conf") == 0) {
        const char *cfg_path = (argc >= 3) ? argv[2] : default_config;
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        return check_config(cfg_path, &cfg);
    } else if (strcmp(cmd, "zones") == 0) {
        const char *cfg_path = (argc >= 3) ? argv[2] : default_config;
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        if (check_config(cfg_path, &cfg) != 0) return 1;

        int error_count = 0;
        int checked = 0;
        zone_config_t *z = cfg.zones;
        while (z) {
            if (!z->type || (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0)) {
                if (check_zone(z->domain, z->file, false) != 0) {
                    error_count++;
                }
                checked++;
            }
            z = z->next;
        }
        printf("[INFO] Checked %d zones. Errors: %d\n", checked, error_count);
        return (error_count > 0) ? 1 : 0;
    } else if (strcmp(cmd, "zone") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        const char *domain = argv[2];
        if (argc >= 4 && strstr(argv[3], ".conf") == NULL && strstr(argv[3], "/") != NULL) {
            // Standalone mode: karicheck zone <domain> <zone_file_path>
            return check_zone(domain, argv[3], true);
        } else {
            // From config: karicheck zone <domain> [config_path]
            const char *cfg_path = (argc >= 4) ? argv[3] : default_config;
            server_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            if (check_config(cfg_path, &cfg) != 0) return 1;

            zone_config_t *z = cfg.zones;
            while (z) {
                if (strcasecmp(z->domain, domain) == 0) {
                    return check_zone(z->domain, z->file, false);
                }
                z = z->next;
            }
            fprintf(stderr, "[ERROR] Zone '%s' not found in config %s\n", domain, cfg_path);
            return 1;
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}

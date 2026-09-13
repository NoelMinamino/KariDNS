#include "dag_batch.h"

int execute_batch_spec(const query_spec_t *spec) {
    if (!spec->batch_file) return 0;
    FILE *bf = fopen(spec->batch_file, "r");
    if (!bf) {
        fprintf(stderr, "error: could not open batch file '%s': %s\n", spec->batch_file, strerror(errno));
        return 8;
    }
    char line[1024];
    int line_num = 0;
    while (fgets(line, sizeof(line), bf)) {
        line_num++;
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        char *line_argv[64];
        int line_argc = 0;
        line_argv[line_argc++] = "dag";
        char *tok = strtok(p, " \t\r\n");
        while (tok && line_argc < 63) {
            line_argv[line_argc++] = tok;
            tok = strtok(NULL, " \t\r\n");
        }
        line_argv[line_argc] = NULL;

        if (line_argc > 1) {
            bool has_cli_only_opt = false;
            for (int k = 1; k < line_argc; k++) {
                if (strcmp(line_argv[k], "-h") == 0 || strcmp(line_argv[k], "--help") == 0 ||
                    strcmp(line_argv[k], "-v") == 0 || strcmp(line_argv[k], "--version") == 0) {
                    fprintf(stderr, "warning: batch line %d ignores CLI-only option '%s'\n", line_num, line_argv[k]);
                    has_cli_only_opt = true;
                    break;
                }
            }
            if (has_cli_only_opt) continue;

#ifndef _WIN32
            pid_t pid = fork();
            if (pid == 0) {
                query_spec_t local_spec;
                init_query_spec(&local_spec);
                deep_copy_query_opts(&local_spec.qo, &spec->qo); // グローバル設定を継承
                local_spec.dopt = spec->dopt;
                if (spec->server_arg) local_spec.server_arg = spec->server_arg;
                if (spec->port != 53) local_spec.port = spec->port;
                prescan_always_global_options(line_argc, line_argv, &local_spec);
                int rc = 0;
                if (parse_arg_slice(1, line_argc, line_argc, line_argv, &local_spec) >= 0) {
                    rc = execute_query_spec(&local_spec);
                } else {
                    fprintf(stderr, "warning: failed to parse batch line %d\n", line_num);
                    rc = 1;
                }
                free_query_opts(&local_spec.qo);
                exit(rc < 0 ? 1 : 0);
            } else if (pid > 0) {
                int status = 0;
                waitpid(pid, &status, 0);
            } else {
                // Fallback if fork fails
                query_spec_t local_spec;
                init_query_spec(&local_spec);
                deep_copy_query_opts(&local_spec.qo, &spec->qo);
                local_spec.dopt = spec->dopt;
                if (spec->server_arg) local_spec.server_arg = spec->server_arg;
                if (spec->port != 53) local_spec.port = spec->port;
                prescan_always_global_options(line_argc, line_argv, &local_spec);
                if (parse_arg_slice(1, line_argc, line_argc, line_argv, &local_spec) >= 0) {
                    execute_query_spec(&local_spec);
                } else {
                    fprintf(stderr, "warning: failed to parse batch line %d\n", line_num);
                }
                free_query_opts(&local_spec.qo);
            }
#else
            query_spec_t local_spec;
            init_query_spec(&local_spec);
            deep_copy_query_opts(&local_spec.qo, &spec->qo); // グローバル設定を継承
            local_spec.dopt = spec->dopt;
            if (spec->server_arg) local_spec.server_arg = spec->server_arg;
            if (spec->port != 53) local_spec.port = spec->port;
            prescan_always_global_options(line_argc, line_argv, &local_spec);
            if (parse_arg_slice(1, line_argc, line_argc, line_argv, &local_spec) >= 0) {
                execute_query_spec(&local_spec);
            } else {
                fprintf(stderr, "warning: failed to parse batch line %d\n", line_num);
            }
            free_query_opts(&local_spec.qo);
#endif
        }
    }
    fclose(bf);
    return 0;
}

#include "dag_batch.h"

/* One line of a batch file (-f), as dig 9.20 runs it. Every line starts from all the options given on the command
 * line (dig clones its default lookup; transport, display, EDNS, TSIG, @server, -p, ...); the options on the line
 * override them, except +[no]tcp / +[no]vc, which dig ignores on batch lines. A line may hold several queries
 * (name / type / class tuples, split like the command line) or none (an empty line queries ". NS", the default
 * query). The first query of the file prints the full banner, the first query of each later line only the
 * "; <<>> dag <<>>" line, further queries on a line none. Lines run in this process, so +keepopen keeps the
 * connection open across lines. */
static int run_batch_line(const query_spec_t *spec, int argc, char **argv, int line_num, bool first) {
    int n = 1;
    for (int k = 1; k < argc; k++) {
        if (strcmp(argv[k], "+tcp") == 0 || strcmp(argv[k], "+notcp") == 0 ||
            strcmp(argv[k], "+vc") == 0 || strcmp(argv[k], "+novc") == 0)
            continue;
        argv[n++] = argv[k];
    }
    argv[n] = NULL;
    argc = n;

    arg_slice_t queries[MAX_DAG_QUERIES];
    int global_end = 1;
    int query_count = split_query_tuples(argc, argv, queries, &global_end);
    if (query_count < 0) {
        fprintf(stderr, "warning: failed to parse batch line %d\n", line_num);
        return 1;
    }
    if (query_count == 0) { /* no name: the default query */
        queries[0].start = queries[0].end = 0;
        query_count = 1;
    }

    query_spec_t line_spec = *spec;
    deep_copy_query_opts(&line_spec.qo, &spec->qo);
    line_spec.batch_file = NULL;
    if (!first) line_spec.qo.cmd_banner_style = CMD_BANNER_LINE;
    prescan_always_global_options(argc, argv, &line_spec);
    int last_rc = 0;
    if (parse_arg_slice(1, global_end, argc, argv, &line_spec) < 0) {
        fprintf(stderr, "warning: failed to parse batch line %d\n", line_num);
        free_query_opts(&line_spec.qo);
        return 1;
    }
    for (int q = 0; q < query_count; q++) {
        query_spec_t local_spec = line_spec;
        deep_copy_query_opts(&local_spec.qo, &line_spec.qo);
        if (q > 0) local_spec.qo.cmd_banner_style = CMD_BANNER_NONE;
        int rc;
        if (queries[q].start < queries[q].end &&
            parse_arg_slice(queries[q].start, queries[q].end, argc, argv, &local_spec) < 0) {
            fprintf(stderr, "warning: failed to parse batch line %d\n", line_num);
            rc = 1;
        } else {
            rc = execute_query_spec(&local_spec);
            finish_query_tuple(&local_spec);
        }
        if (rc != 0) last_rc = rc;
        free_query_opts(&local_spec.qo);
    }
    free_query_opts(&line_spec.qo);
    return last_rc;
}

/* Returns the exit status of the last query that failed (0 when all succeeded), like several queries given on
 * the command line; dig also exits with 9 when the servers of a batch line could not be reached.
 * Like dig, lines starting with '#', ';' or a line end are skipped only before the first query; later lines are
 * always queries (dig reads them without that check), e.g. "; note" queries ";." and "note.". */
int execute_batch_spec(const query_spec_t *spec) {
    if (!spec->batch_file) return 0;
    FILE *bf = fopen(spec->batch_file, "r");
    if (!bf) {
        fprintf(stderr, "error: could not open batch file '%s': %s\n", spec->batch_file, strerror(errno));
        return 8;
    }
    char line[1024];
    int line_num = 0;
    int last_rc = 0;
    int lines_run = 0;
    while (fgets(line, sizeof(line), bf)) {
        line_num++;
        if (lines_run == 0 && (line[0] == '#' || line[0] == ';' || line[0] == '\n' || line[0] == '\r')) continue;

        char *line_argv[64];
        int line_argc = 0;
        line_argv[line_argc++] = "dag";
        char *tok = strtok(line, " \t\r\n");
        while (tok && line_argc < 63) {
            line_argv[line_argc++] = tok;
            tok = strtok(NULL, " \t\r\n");
        }
        line_argv[line_argc] = NULL;

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
        int rc = run_batch_line(spec, line_argc, line_argv, line_num, lines_run++ == 0);
        if (rc != 0) last_rc = rc;
    }
    fclose(bf);
    return last_rc;
}

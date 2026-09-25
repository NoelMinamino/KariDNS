/* Compiles tools/karictl.c into test_coverage_sweep_tools with main() renamed,
 * so the sweep can drive karictl's real command-line flow.
 * read_entire_file is renamed as well: dns_config_parser.c (linked into the
 * same binary for karicheck) exports a function with the same name. */
#define main karictl_main
#define read_entire_file karictl_read_entire_file
#include "../tools/karictl.c"

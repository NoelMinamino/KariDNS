/* Compiles tools/karictl.c into test_coverage_sweep_tools with main() renamed,
 * so the sweep can drive karictl's real command-line flow. */
#define main karictl_main
#include "../tools/karictl.c"

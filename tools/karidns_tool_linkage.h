/*
 * karidns_tool_linkage.h - linkage of the CLI tools' internal helpers.
 *
 * The unit tests and fuzzers exercise dag.c / karicheck.c by #including them.
 * For a function with internal linkage, clang's profile name is prefixed with
 * the *including* translation unit, so every binary that includes the file
 * gets its own copy of each helper's counters, and llvm-cov reports only the
 * best single copy instead of their union. Coverage builds therefore define
 * KARIDNS_COVERAGE_LINKAGE, which gives these helpers external linkage (and
 * one shared profile name); normal builds keep them static.
 */
#ifndef KARIDNS_TOOL_LINKAGE_H
#define KARIDNS_TOOL_LINKAGE_H

#ifdef KARIDNS_COVERAGE_LINKAGE
#define KARIDNS_TOOL_FN
#define KARIDNS_TOOL_FN_INLINE
#else
#define KARIDNS_TOOL_FN static
#define KARIDNS_TOOL_FN_INLINE static inline
#endif

#endif /* KARIDNS_TOOL_LINKAGE_H */

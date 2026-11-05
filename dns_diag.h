#ifndef DNS_DIAG_H
#define DNS_DIAG_H

/*
 * dns_diag.h - the diagnostic sink of the configuration parser, the zone checks and karicheck.
 *
 * Every "[ERROR] ..." / "[WARNING] ..." / "[INFO] ..." / "[NOTE] ..." line these print goes through dns_diag().  Without JSON mode (karidns,
 * and karicheck without --json) it prints exactly the line it always printed: the tag, then the message, on stderr (on stdout for INFO),
 * and nothing is kept.  In JSON mode (karicheck --json) it keeps the message with its code, its place and the zone it is about, and
 * dns_diag_json_finish() writes everything as one JSON document (docs/karicheck.md, "JSON OUTPUT").
 *
 * Every message has a code (dns_diag_codes.h): the call takes the enum, so a message without a code does not compile.
 * Ordinary process code (malloc allowed); the server only ever uses the text path, which allocates nothing.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef enum {
    DC_NONE = 0,
#define X(id, name, sev, desc) DC_##id,
#define XR(id, name, sev, desc) DC_##id,
#include "dns_diag_codes.h"
#undef X
#undef XR
    DC__COUNT
} dns_diag_code_t;

/* severities; or-ed with the flags */
#define DIAG_ERROR 0
#define DIAG_WARNING 1
#define DIAG_NOTE 2
#define DIAG_INFO 3
#define DIAG_SEV_MASK 0xff
#define DIAG_UNTAGGED 0x100     /* text mode prints no "[TAG] " in front of the message */
#define DIAG_STDERR 0x200       /* text mode prints an INFO on stderr (the others go to stderr anyway) */

#define DIAG_MAX_MESSAGES 10000 /* JSON mode keeps this many messages, the rest is only counted ("truncated": true) */
#define DIAG_MAX_ZONES 100000   /* ... and this many entries of zones[] */
#define DIAG_TEXT_MAX 4096      /* a message longer than this is cut in the JSON output */

/* One message.  file / line: where it was found (file NULL = unknown, line <= 0 = unknown); JSON mode fills in the context set with
 * dns_diag_set_context() / dns_diag_set_line() for what the call leaves out.  The text is the printf result as it is printed today, so it
 * normally ends with a line feed; JSON mode drops the final line feeds. */
void dns_diag(int sev, dns_diag_code_t code, const char *file, long line, const char *fmt, ...) __attribute__((format(printf, 5, 6)));
void dns_vdiag(int sev, dns_diag_code_t code, const char *file, long line, const char *fmt, va_list ap);
/* The same with the place as the text the configuration parser builds: "file:line", "line N" or NULL */
void dns_diag_at(int sev, dns_diag_code_t code, const char *loc, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
void dns_vdiag_at(int sev, dns_diag_code_t code, const char *loc, const char *fmt, va_list ap);
/* A continuation line of the message before it (stderr, no tag; the text carries its own indent).  JSON mode appends it to that message,
 * after a line feed. */
void dns_diag_detail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void dns_vdiag_detail(const char *fmt, va_list ap);
/* Output that is no diagnostic ("[OK] ...", "[RESULT] ...", "[FAIL] ...", the source line of a syntax error): printed in text mode,
 * dropped in JSON mode (the document says the same in structured form). */
void dns_diag_plain(FILE *fp, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void dns_vdiag_plain(FILE *fp, const char *fmt, va_list ap);
/* "[OK] ..." on stdout (a check that passed, no diagnostic): printed in text mode, dropped in JSON mode */
void dns_vdiag_ok(const char *fmt, va_list ap);

/* ---- JSON mode (karicheck --json) ---- */
/* JSON mode is on and not suspended */
bool dns_diag_json_enabled(void);
/* Suspend (true) or resume (false) JSON mode: while it is suspended the messages are printed as in text mode.  Returns the previous state.
 * karicheck uses it where the configuration parser runs with its stderr redirected to learn the reason of an error. */
bool dns_diag_suspend_json(bool suspend);
/* Switch to JSON mode (once, at the start of the run).  command: "conf", "zones", "zone", "db" (karicheck), "import", "export" (karidns-zone) or NULL (usage error before a command). */
void dns_diag_json_start(const char *command, const char *version);
/* The first key of the document is the name of the tool (default "karicheck"): karidns-zone calls this after dns_diag_json_start().  The schema is the same. */
void dns_diag_json_tool(const char *tool);
/* What the following messages are about; NULL clears.  JSON mode only. */
void dns_diag_set_file(const char *file);                   /* the file a message is about when it names none */
void dns_diag_set_zone(const char *zone, const char *view);
void dns_diag_set_line(long line);          /* the line the following messages are about (0 = none) */
typedef struct { size_t errors, warnings; } dns_diag_mark_t;
dns_diag_mark_t dns_diag_mark(void);        /* the error and warning counts so far */
/* Add an entry to zones[]: the messages (errors, warnings) counted since `since` decide the result.  view / file / format may be NULL. */
void dns_diag_zone_result(const char *zone, const char *view, const char *file, const char *format, dns_diag_mark_t since);
void dns_diag_counts(unsigned checked, unsigned skipped);
/* Write the document and leave JSON mode's state as it is.  status: the exit status of the run (0 ok, 1 fail, 2 usage error).
 * Returns 0, or -1 when the document could not be written. */
int dns_diag_json_finish(FILE *fp, int status);
/* Free what JSON mode keeps and leave JSON mode (tests; karicheck lets the process end) */
void dns_diag_json_reset(void);

/* JSON string content for in[0..n): '"' and '\\' escaped, every byte below 0x20 and 0x7F as \u00XX, a byte that is not part of a valid
 * UTF-8 sequence replaced by U+FFFD.  The result goes to out like snprintf(): at most cap - 1 bytes and a NUL; returns the length the full
 * result has. */
size_t dns_diag_json_escape(char *out, size_t cap, const char *in, size_t n);

/* ---- test builds only (-DKARIDNS_DIAG_CODELOG: karicheck-codelog, the unit tests): append the code of every message to a file.  The shipped
 * binaries have no such function and read no environment variable for it. ---- */
#ifdef KARIDNS_DIAG_CODELOG
void dns_diag_code_log(const char *path);
/* Add a code to that file without printing anything (the checks that hand their findings to a sink, and the tests that read them) */
void dns_diag_code_note(dns_diag_code_t code);
#else
#define dns_diag_code_note(code) ((void)(code))
#endif

/* ---- the code table ---- */
const char *dns_diag_code_name(dns_diag_code_t code);       /* "zone.soa.missing"; "" for DC_NONE or a value out of range */
dns_diag_code_t dns_diag_code_find(const char *name);       /* DC_NONE when there is no such code */
char dns_diag_code_severity(dns_diag_code_t code);          /* the default severity: 'E' 'W' 'N' 'I' */
const char *dns_diag_code_desc(dns_diag_code_t code);
bool dns_diag_code_retired(dns_diag_code_t code);

#endif /* DNS_DIAG_H */

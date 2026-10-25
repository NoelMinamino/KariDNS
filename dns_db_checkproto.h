#ifndef DNS_DB_CHECKPROTO_H
#define DNS_DB_CHECKPROTO_H

/*
 * dns_db_checkproto.h - the line protocol between `karidns-dbloader --check` and `karicheck db` (B12, beta design 7.2).
 *
 * The loader writes what it finds on its standard output, one finding per line; karicheck reads the lines through a pipe and prints
 * them in its own style.  The loader runs with the rights of the loader user, so karicheck (which may be root) reads the lines as
 * untrusted input: every field is bounded, the escapes are strict, and nothing a line says is trusted to be printable.
 *
 * A line is TAB separated fields, ended by LF.  Field 0 is a one-letter tag:
 *   E W I O D  <zone> <id> <text>    a finding: error, warning, information, ok, detail (continuation of the finding before)
 *                                    zone: the canonical zone name ("" = about the source, not a zone), id: domains.id (0 = none)
 *   Z  <zone> <id> <kind> <view>...  a zone of the source (before its findings): kind primary | secondary | catalog | other;
 *                                    the views of karidns_domain_views that name it ("*" = it has no row: every view of the source)
 *   S  <zone> <id> <text> <profile> <profile-text>
 *                                    the settings text of a zone (what the loader would send in ZONE_BEGIN) and the profile it names
 *   R  <zones> <errors> <warnings>   the end of a run: zones read, findings counted by the loader
 * Text fields are escaped: a byte outside 0x20..0x7E and the backslash are written \DDD (three decimal digits), so a field never
 * contains a TAB or LF.  A line that does not start with a tag and a TAB is not part of the protocol (a message of the C library on
 * standard error, say); karicheck prints it after chk_printable().
 */

#include <stddef.h>
#include <stdbool.h>

#define CHK_LINE_MAX 262144         /* the longest line karicheck accepts (a settings text of 64 KiB escapes to about 4 times that) */
#define CHK_MAX_FIELDS 64           /* fields of a line (Z lines list the views of a zone) */
#define CHK_TEXT_MAX 1000           /* the loader cuts a finding at this many source bytes */

/* in[0..n) into out (NUL terminated, at most cap - 1 bytes, an escape is never cut).  Returns the length; *trunc is set when the
 * input did not fit. */
size_t chk_escape(const char *in, size_t n, char *out, size_t cap, bool *trunc);
/* The inverse: in[0..n) of escaped text into out (NUL terminated).  Returns the length, or (size_t)-1 for a malformed escape (a
 * backslash not followed by three digits, a value above 255) or when the result does not fit cap - 1 bytes.  A byte outside
 * 0x20..0x7E in the input is malformed too. */
size_t chk_unescape(const char *in, size_t n, char *out, size_t cap);
/* Split line (without its LF; modified: TABs become NULs) into at most max fields.  Returns the number of fields, or -1 when there
 * are more than max or the line has a byte below 0x20 other than TAB. */
int chk_split(char *line, char **fields, int max);
/* Make s printable in place: a byte outside 0x20..0x7E becomes '?' */
void chk_printable(char *s);

#endif /* DNS_DB_CHECKPROTO_H */

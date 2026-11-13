#!/bin/sh
# run_md2man_test.sh - the manual pages generated from the Markdown manuals (0.7; man/md2man.pl, man/generate.sh, docs/RELEASING.md).
#
#   1. the converter on the fixtures of tests/md2man/: every construct the manuals use (constructs.md -> constructs.8) and text that roff
#      would take for its own (hostile.md -> hostile.1) give the expected pages byte for byte;
#   2. in the fixtures' output and in every page of man/: no line starts with "." or "'" unless it is one of the macros the converter writes,
#      no character outside ASCII, every escape is one the converter writes (\e \- \& \fB \fI \fR \f(BI \(bu \(em \(dq \[uXXXX]);
#   3. the usage errors (no section, no name, two files) exit non-zero and write nothing;
#   4. the pages of man/ are fresh: man/generate.sh into a scratch directory gives the committed pages byte for byte (run `make man` and
#      commit the pages after changing a manual);
#   5. mandoc -T lint: no message at WARNING or worse in any page or fixture output (STYLE messages are printed, not failed); the pages
#      render in an 80-column terminal (mandoc -T utf8 -O width=80), the lines wider than that (code blocks, which are not wrapped) counted.
# SKIP without perl (the whole test) and without mandoc (part 5); with KARIDNS_TEST_REQUIRE=1 (CI) either is a failure instead.  A page or
# fixture with CR LF line ends (a checkout made before .gitattributes said eol=lf) is compared and checked without the CRs.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
done_() { echo; echo "=== run_md2man_test: $FAILS failed, $PASS passed ==="; [ "$FAILS" = 0 ]; exit $?; }

# skip WHAT: a SKIP, or a failure when KARIDNS_TEST_REQUIRE=1 (CI: the gate must run)
skip() { if [ "${KARIDNS_TEST_REQUIRE:-0}" = 1 ]; then bad "$1 (KARIDNS_TEST_REQUIRE=1: no SKIP)"; done_; fi; echo "SKIP: $1"; }
command -v perl > /dev/null 2>&1 || { skip "perl is not installed"; exit 0; }
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_md2man.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
trap 'exit 130' INT TERM
PAGES="karidns.8 karidns.conf.5 karictl.8 karicheck.8 dag.1 dag-replay.1 karidns-tapstat.1 karidns-dbloader.8 karidns-zone.8 karidns-signer.8 karidns-webadmin.8"
# the committed pages and fixtures without CRs (above): what is compared, checked and linted
mkdir "$T/man" "$T/fix"
for p in $PAGES; do [ -f "man/$p" ] && tr -d '\r' < "man/$p" > "$T/man/$p"; done
for f in constructs.8 hostile.1; do tr -d '\r' < "tests/md2man/$f" > "$T/fix/$f"; done

echo "-- the converter on the fixtures"
perl man/md2man.pl -s 8 -n example-tool -d 2026-11-13 tests/md2man/constructs.md > "$T/constructs.8" 2> "$T/err" || bad "constructs.md: the converter failed" "$(cat "$T/err")"
cmp -s "$T/constructs.8" "$T/fix/constructs.8" && ok "constructs.md gives tests/md2man/constructs.8" || bad "constructs.md: the page differs" "$(diff tests/md2man/constructs.8 "$T/constructs.8")"
perl man/md2man.pl -s 1 -n hostile -d 2026-11-13 tests/md2man/hostile.md > "$T/hostile.1" 2> "$T/err" || bad "hostile.md: the converter failed" "$(cat "$T/err")"
cmp -s "$T/hostile.1" "$T/fix/hostile.1" && ok "hostile.md gives tests/md2man/hostile.1" || bad "hostile.md: the page differs" "$(diff tests/md2man/hostile.1 "$T/hostile.1")"
# what the fixtures must show, said once more in words
grep -q '^\\&\.TH FAKE' "$T/hostile.1" && grep -q "^\\\\&'item" "$T/hostile.1" && grep -q '^\\&\.SH inside a code block' "$T/hostile.1" && ok "a line that starts with . or ' gets \\& before it (text, item, code)" || bad "a leading . or ' is not escaped"
grep -q 'with \\efBa font escape\\efR' "$T/hostile.1" && grep -q '^\\efB backslash in code' "$T/hostile.1" && ok "a backslash is \\e (text and code)" || bad "a backslash is not \\e"
grep -q '^\\-  \\-\\-options\\-in\\-code' "$T/hostile.1" && grep -q '\\fB\\-c\\fR and \\-\\-check' "$T/constructs.8" && ok "the hyphens of an option are \\- (code and text)" || bad "an option's hyphen is not \\-"
grep -q 'ASCII: \\\[u00E9\] \\\[u2014\] \\\[u2713\] \\\[u65E5\]\\\[u672C\]' "$T/hostile.1" && ok "characters outside ASCII are \\[uXXXX]" || bad "a character outside ASCII is not \\[uXXXX]"
grep -q '^\.SH \.SH \\(dqA HEADING\\(dq' "$T/hostile.1" && ok "a double quote in a heading is \\(dq" || bad "a double quote in .SH is not escaped"
grep -q '^\\&\.cell	\\&_$' "$T/hostile.1" && grep -q '^\\&=	\\&T{$' "$T/hostile.1" && ok "table cells start with \\& (_, = and T{ stay text)" || bad "a table cell is not protected"
grep -q '^lb lbw(46) lb$' "$T/constructs.8" && grep -q '	T{$' "$T/constructs.8" && grep -q '^T}	' "$T/constructs.8" && ok "a table too wide for 80 columns with short words is wrapped (tbl text blocks)" || bad "no wrapped table"
grep -q '^\\fIDefault:\\fR none$' "$T/constructs.8" && ok "a table that cannot fit becomes a tagged list (Header: text)" || bad "no tagged list"
grep -q '^\\fBWarning:\\fR A callout of two lines\.$' "$T/constructs.8" && ok "a callout starts with its kind" || bad "callout"
grep -q '^\.IP 2\. 4$' "$T/constructs.8" && grep -q '^\.RS 4$' "$T/constructs.8" && ok "ordered and nested lists" || bad "lists"
grep -q '^\.TP 8$' "$T/constructs.8" && grep -q '^A second paragraph of the option\.$' "$T/constructs.8" && ok "definition lists with a second paragraph" || bad "definition lists"
grep -q 'EXAMPLE-TOOL(8)\|September 2026' "$T/constructs.8" && bad "the page header or footer repeated in a code block is left in" || ok "the code blocks that repeat the page header and footer are dropped"
grep -q '\\f(BIboth\\fR' "$T/constructs.8" && grep -q 'db/\*\.sql that stays' "$T/constructs.8" && grep -q 'an escaped \* star' "$T/constructs.8" && ok "bold italic, a lone * and an escaped \\* " || bad "emphasis"
grep -q '<https://www.example.org/wiki/Name_(disambiguation)> keeps its whole address' "$T/constructs.8" && grep -q 'link in parentheses <https://www.example.org/a>)' "$T/constructs.8" && ok "a link whose address holds parentheses keeps all of it, and one in parentheses the closing one" || bad "links with parentheses"
sed -n '/^Numbered with/,/^\.IP \\(bu/p' "$T/constructs.8" | grep '^\.IP' | tr '\n' ' ' | grep -qx '\.IP 1\. 4 \.IP 2\. 4 \.IP 3\. 4 \.IP 7\. 4 \.IP 8\. 4 \.IP \\(bu 2 ' && ok "ordered lists are counted from their first number (1. 1. 1. and 7) 7))" || bad "ordered list numbers" "$(sed -n '/^Numbered with/,/^\.IP \\(bu/p' "$T/constructs.8" | grep '^\.IP')"
awk '/^T\{$|	T\{$/ { blk = 1; next } blk && /^T\}/ { if ($0 != "T}" && $0 !~ /^T\}	/) bad = 1; blk = 0 } END { exit bad }' "$T/hostile.1" && grep -q '^\\&T} T} T}' "$T/hostile.1" && ok "a wrapped cell line that starts with T} gets \\& (it would end the text block)" || bad "a cell line T} ends the text block" "$(grep -n '^T}\|^\\&T}' "$T/hostile.1" | head -5)"

echo "-- every line and escape of the output"
# check FILE: the lines and escapes the converter may write
check() {
    awk -v f="$1" '
        /^\.TS$/ { tbl = 1 } /^\.TE$/ { tbl = 0 }
        /^[.]/ && $0 !~ /^\.(TH|SH|SS|PP|IP|TP|RS|RE|nf|fi|br|TS|TE)( |$)/ && $0 !~ /^\.\\" / { print f ": " NR ": a line that is a request: " $0; bad = 1 }
        /^'"'"'/ { print f ": " NR ": a line that starts with an apostrophe: " $0; bad = 1 }
        { s = $0; gsub(/\\(e|-|&|f[BIRP]|f\(BI|\(bu|\(em|\(dq|\[u[0-9A-F][0-9A-F][0-9A-F][0-9A-F]+\])/, "", s); if (index(s, "\\") && $0 !~ /^\.\\" /) { print f ": " NR ": an escape the converter does not write: " $0; bad = 1 } }
        END { exit bad }' "$1"
    LC_ALL=C grep -n '[^[:print:]	]' "$1" | head -3 | sed "s|^|$1: outside ASCII: |"
    ! LC_ALL=C grep -q '[^[:print:]	]' "$1"
}
for f in "$T/constructs.8" "$T/hostile.1"; do check "$f" > "$T/check.out" && ok "$(basename "$f"): only the macros and escapes of the converter" || bad "$(basename "$f")" "$(cat "$T/check.out")"; done
all=0
for p in $PAGES; do [ -f "man/$p" ] || { bad "man/$p is missing"; continue; }; check "$T/man/$p" >> "$T/pages.out" || all=1; done
[ $all = 0 ] && ok "the pages of man/: only the macros and escapes of the converter" || bad "the pages of man/" "$(cat "$T/pages.out")"

echo "-- usage errors"
for args in "-n x tests/md2man/constructs.md" "-s 8 tests/md2man/constructs.md" "-s 8 -n x tests/md2man/constructs.md tests/md2man/hostile.md" "-s 8 -n x -d 1;2 tests/md2man/constructs.md" "-s 8 -n x /nonexistent.md"; do
    # shellcheck disable=SC2086
    if perl man/md2man.pl $args > "$T/u.out" 2> /dev/null; then bad "md2man.pl $args succeeded"; elif [ -s "$T/u.out" ]; then bad "md2man.pl $args wrote output"; else ok "md2man.pl $args: an error, no output"; fi
done

echo "-- the pages are fresh"
mkdir "$T/fresh"
if sh man/generate.sh "$T/fresh" > "$T/gen.out" 2>&1; then
    stale=""
    for p in $PAGES; do cmp -s "$T/man/$p" "$T/fresh/$p" || stale="$stale $p"; done
    extra=$(cd "$T/fresh" && ls | grep -v -x -F "$(printf '%s\n' $PAGES)")
    [ -z "$stale" ] && ok "man/generate.sh gives the committed pages" || bad "stale pages (run make man and commit them):$stale" "$(for p in $stale; do diff "man/$p" "$T/fresh/$p" | head -6; done)"
    [ -z "$extra" ] && ok "...and no page that is not tested here" || bad "man/generate.sh writes pages this test does not know: $extra"
else
    bad "man/generate.sh failed" "$(cat "$T/gen.out")"
fi

echo "-- mandoc"
command -v mandoc > /dev/null 2>&1 || { skip "mandoc is not installed: the lint and the rendering"; done_; }
for f in "$T/constructs.8" "$T/hostile.1"; do
    mandoc -T lint -W warning "$f" > "$T/lint.out" 2>&1
    [ ! -s "$T/lint.out" ] && ok "mandoc -T lint: nothing at WARNING or worse in $(basename "$f")" || bad "mandoc -T lint $(basename "$f")" "$(cat "$T/lint.out")"
done
for p in $PAGES; do
    mandoc -T lint -W warning "$T/man/$p" > "$T/lint.out" 2>&1
    [ ! -s "$T/lint.out" ] && ok "mandoc -T lint: nothing at WARNING or worse in man/$p" || bad "mandoc -T lint man/$p" "$(cat "$T/lint.out")"
    mandoc -T lint -W style "$T/man/$p" 2>&1 | sed 's/^/         (style) /' | head -5
    if mandoc -T utf8 -O width=80 "$T/man/$p" > "$T/page.txt" 2> "$T/render.err" && [ -s "$T/page.txt" ] && [ ! -s "$T/render.err" ]; then
        wide=$(col -bx < "$T/page.txt" | LC_ALL=C.UTF-8 awk 'length > 80' | wc -l | tr -d ' ')
        ok "man/$p renders at 80 columns ($wide line(s) wider: code blocks)"
    else
        bad "man/$p does not render" "$(cat "$T/render.err")"
    fi
done
done_

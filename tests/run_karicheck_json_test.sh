#!/bin/sh
# run_karicheck_json_test.sh - `karicheck --json`: the JSON document of conf, zones, zone and db (planing 0.6.x karicheck --json).
#
# For every command: a run that is clean, one with warnings and one with errors; the document must be valid JSON of the documented
# shape (tests/lib/json_check.pl: schema, the codes against dns_diag_codes.h, the counts against the messages), stdout must hold only
# that document, stderr nothing, and the exit status must be the one the text mode gives for the same arguments.  Then the zone text
# from standard input (`zone <domain> -`: clean, syntax error, $INCLUDE refused, exactly 64 MiB, one byte more), usage errors
# (exit 2 with a usage.* message), the database (SQLite3, needs the sqlite3 tool and karidns-dbloader), and hostile input: file
# names with quotes, backslashes, line feeds and invalid UTF-8, owner names with control characters and bytes above 127, a zone name
# that is not a name, a configuration that names such zones.
#
# SKIP (exit 0, with the reason) without karicheck or without perl's JSON::PP.  The db part SKIPs without karidns-dbloader (SQLite3
# driver) or the sqlite3 tool.  Run as a normal user and as root (the loader of the db part runs as SUDO_USER or nobody then).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

KC=${KC:-$ROOT/karicheck}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
JC="perl $ROOT/tests/lib/json_check.pl"
[ -x "$KC" ] || { echo "SKIP: karicheck is not built"; exit 0; }
perl -MJSON::PP -e 1 >/dev/null 2>&1 || { echo "SKIP: perl with JSON::PP is not installed"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karicheck_json.XXXXXX") || exit 1
chmod 755 "$T"
trap 'if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"; fi' EXIT INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -16 | sed 's/^/         /'; }

OUT=$T/out.json
ERR=$T/err.txt

# jrun DESC WANT-STATUS ARGS...: karicheck --json ARGS (stdin from /dev/null, or from $STDIN_FILE); checks the status, an empty stderr, a valid
# document, and the status of the text mode with the same ARGS.  $? of the last run is in $st.
jrun() {
    desc=$1; want=$2; shift 2
    if [ -n "${STDIN_FILE:-}" ]; then "$KC" --json "$@" < "$STDIN_FILE" > "$OUT" 2> "$ERR"; else "$KC" --json "$@" < /dev/null > "$OUT" 2> "$ERR"; fi
    st=$?
    if [ "$st" != "$want" ]; then bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 600 "$OUT")"; return 1; fi
    if [ -s "$ERR" ]; then bad "$desc: stderr is not empty" "$(cat "$ERR")"; return 1; fi
    if ! msg=$($JC "$OUT" valid 2>&1); then bad "$desc: $msg" "$(head -c 1200 "$OUT")"; return 1; fi
    if [ -n "${STDIN_FILE:-}" ]; then "$KC" "$@" < "$STDIN_FILE" > /dev/null 2>&1; else "$KC" "$@" < /dev/null > /dev/null 2>&1; fi
    tst=$?
    if [ "$tst" != "$st" ]; then bad "$desc: the text mode exits with $tst, --json with $st"; return 1; fi
    return 0
}
# want DESC PATH EXPECTED: the first value at PATH in $OUT
want() {
    got=$($JC "$OUT" get "$2" 2>&1)
    if [ "$got" = "$3" ]; then ok "$1"; else bad "$1 ($2: got '$got', wanted '$3')" "$(head -c 1500 "$OUT")"; fi
}
has() { if $JC "$OUT" has "$2"; then ok "$1"; else bad "$1 (no message with code $2)" "$(head -c 1500 "$OUT")"; fi; }
hasnt() { if $JC "$OUT" has "$2"; then bad "$1 (a message has code $2)" "$(head -c 1500 "$OUT")"; else ok "$1"; fi; }

# ---------------------------------------------------------------- fixtures
HDR='$ORIGIN %s\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.2\n'
mkzone() {          # mkzone FILE ORIGIN [EXTRA-LINES]
    printf "$HDR" "$2" > "$1"
    [ -n "${3:-}" ] && printf '%s\n' "$3" >> "$1"
}
mkzone "$T/good.zone" ex.test.
mkzone "$T/warn.zone" warn.test. 'a IN CNAME b
b IN CNAME www'
mkzone "$T/lint.zone" lint.test. '@ IN NS ns9'
mkzone "$T/bad.zone" bad.test. 'bad IN A 999.1.1.1'

cat > "$T/good.conf" <<EOF
options { directory "$T"; };
zone "ex.test" { type master; file "$T/good.zone"; };
zone "sec.test" { type slave; masters { 192.0.2.9; }; file "$T/sec.db"; };
EOF
cat > "$T/zones.conf" <<EOF
options { directory "$T"; };
zone "ex.test" { type master; file "$T/good.zone"; };
zone "warn.test" { type master; file "$T/warn.zone"; };
zone "lint.test" { type master; file "$T/lint.zone"; };
zone "bad.test" { type master; file "$T/bad.zone"; };
zone "sec.test" { type slave; masters { 192.0.2.9; }; file "$T/sec.db"; };
EOF
cat > "$T/warn.conf" <<EOF
options { directory "$T"; transfers-in 0; startup-notify-rate 5; };
zone "ex.test" { type master; file "$T/good.zone"; };
EOF
cat > "$T/bad.conf" <<EOF
options { directory "$T"; no-such-option yes; };
zone "ex.test" { type master; file "$T/good.zone"; };
EOF
cat > "$T/views.conf" <<EOF
options { directory "$T"; };
view "inside" { match-clients { 192.0.2.0/24; }; zone "ex.test" { type master; file "$T/good.zone"; }; };
view "outside" { match-clients { any; }; zone "ex.test" { type master; file "$T/bad.zone"; }; };
EOF

# ---------------------------------------------------------------- conf
echo "== conf"
if jrun "conf, clean" 0 conf "$T/good.conf"; then
    want "conf: command" command conf
    want "conf: result" result ok
    want "conf: no errors" counts.error 0
    has "conf: the file that is loaded" conf.loading
    want "conf: the file of the first message" messages.0.text "Loading config $T/good.conf..."
    want "conf: info severity" messages.0.severity info
    want "conf: no zones[] entries" zones "[]"
fi
if jrun "conf, warnings and notes" 0 conf "$T/warn.conf"; then
    want "conf: result with warnings" result ok
    want "conf: warning count" counts.warning 1
    has "conf: transfers-in 0" conf.transfers-in-zero
    has "conf: startup-notify-rate note" conf.startup-notify-rate
    want "conf: a note has the severity note" messages.2.severity note
fi
if jrun "conf, errors" 1 conf "$T/bad.conf"; then
    want "conf: result fail" result fail
    has "conf: unknown option in options" conf.syntax
    has "conf: the parse failed" conf.parse-failed
    want "conf: the parser's message has file and line" messages.1.file "$T/bad.conf"
    want "conf: the line of the parser's message" messages.1.line 1
fi
printf 'options { directory "%s"; };
zone "ex.test" { type master; file "%s/good.zone"; no-such-statement yes; };
' "$T" "$T" > "$T/bad2.conf"
if jrun "conf, an unknown statement in a zone" 1 conf "$T/bad2.conf"; then
    has "conf: unknown statement in a zone" conf.option.unknown
    want "conf: the unknown statement has file and line" messages.1.line 2
fi
jrun "conf, no such file" 1 conf "$T/nothing.conf" && has "conf: no such file" io.open
printf 'options { directory ' > "$T/trunc.conf"
jrun "conf, truncated file" 1 conf "$T/trunc.conf" && has "conf: truncated file" conf.parse-failed
mkdir "$T/adir"
jrun "conf, a directory" 1 conf "$T/adir" && has "conf: a directory" io.not-regular

# ---------------------------------------------------------------- zones
echo "== zones"
if jrun "zones" 1 zones "$T/zones.conf"; then
    want "zones: command" command zones
    want "zones: checked" counts.checked 4
    want "zones: skipped" counts.skipped 1
    want "zones: errors" counts.error 2
    has "zones: a skipped zone" zone.skipped
    has "zones: the summary" zone.summary
    has "zones: a CNAME chain" zone.cname.chain
    has "zones: a missing glue record" zone.glue.missing
    has "zones: a syntax error" zone.syntax
    want "zones: four entries" zones.3.zone bad.test.
    want "zones: ex.test ok" zones.0.result ok
    want "zones: its file" zones.0.file "$T/good.zone"
    want "zones: its format" zones.0.format bind
    want "zones: the view is the default one" zones.0.view __default__
    want "zones: warn.test has one warning" zones.1.warnings 1
    want "zones: warn.test still ok" zones.1.result ok
    want "zones: lint.test fails" zones.2.result fail
    want "zones: bad.test fails" zones.3.result fail
fi
if jrun "zones, views" 1 zones "$T/views.conf"; then
    want "views: first view" zones.0.view inside
    want "views: second view" zones.1.view outside
    want "views: first view result" zones.0.result ok
    want "views: second view result" zones.1.result fail
fi
jrun "zones, the configuration is bad" 1 zones "$T/bad.conf" && want "zones: nothing checked" counts.checked 0

# ---------------------------------------------------------------- zone
echo "== zone"
if jrun "zone with a configuration" 0 zone ex.test "$T/good.conf"; then
    want "zone: command" command zone
    want "zone: checked" counts.checked 1
    want "zone: entry" zones.0.zone ex.test.
fi
if jrun "zone with a configuration, errors" 1 zone bad.test "$T/zones.conf"; then
    has "zone/conf: syntax error" zone.syntax
fi
jrun "zone not in the configuration" 1 zone nothing.test "$T/good.conf" && has "zone: not found" zone.not-found
jrun "zone of another type" 1 zone sec.test "$T/good.conf" && true
# standalone
if jrun "zone, a file" 0 zone ex.test "$T/good.zone"; then
    want "standalone: no errors" counts.error 0
    want "standalone: the file" zones.0.file "$T/good.zone"
    want "standalone: no view" zones.0.view null
fi
if jrun "zone, a file with warnings" 0 zone warn.test "$T/warn.zone"; then
    has "standalone: CNAME chain" zone.cname.chain
    want "standalone: severity" messages.0.severity warning
    want "standalone: the zone of a message" messages.0.zone warn.test.
    want "standalone: the file of a message" messages.0.file "$T/warn.zone"
    want "standalone: result ok" result ok
fi
if jrun "zone, a lint error" 1 zone lint.test "$T/lint.zone"; then
    has "standalone: missing glue" zone.glue.missing
    want "standalone: error count" counts.error 1
    want "standalone: failed zone" zones.0.result fail
fi
if jrun "zone, a syntax error" 1 zone bad.test "$T/bad.zone"; then
    want "syntax: code" messages.0.code zone.syntax
    want "syntax: line" messages.0.line 7
    want "syntax: file" messages.0.file "$T/bad.zone"
    want "syntax: the text names the reason" messages.0.text "Syntax error in $T/bad.zone at line 7
Reason: invalid IPv4 address literal in A record"
fi
jrun "zone, no such file" 1 zone ex.test "$T/nothing.zone" && has "standalone: no such file" io.open

# ---------------------------------------------------------------- standard input
echo "== zone from standard input"
STDIN_FILE=$T/good.zone
if jrun "stdin, clean" 0 zone ex.test -; then
    want "stdin: file" zones.0.file "<stdin>"
    want "stdin: zone" zones.0.zone ex.test.
    want "stdin: checked" counts.checked 1
fi
STDIN_FILE=$T/warn.zone
jrun "stdin, warnings" 0 zone warn.test - && has "stdin: CNAME chain" zone.cname.chain
STDIN_FILE=$T/bad.zone
if jrun "stdin, syntax error" 1 zone bad.test -; then
    want "stdin: syntax error file" messages.0.file "<stdin>"
    want "stdin: syntax error line" messages.0.line 7
fi
mkzone "$T/inc.zone" inc.test. '$INCLUDE other.zone'
printf 'x IN A 192.0.2.77\n' > "$T/other.zone"
STDIN_FILE=$T/inc.zone
if jrun "stdin, \$INCLUDE" 1 zone inc.test -; then
    has "stdin: \$INCLUDE is refused" zone.include-stdin
    hasnt "stdin: not a plain syntax error" zone.syntax
fi
jrun "a file with \$INCLUDE still works" 0 zone inc.test "$T/inc.zone"
# the size limit: 64 MiB exactly is accepted, one byte more is refused
LIMIT=67108864
base=$(wc -c < "$T/good.zone")
{ cat "$T/good.zone"; yes ';cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' | head -c $((LIMIT - base)); } > "$T/big_ok.zone"
{ cat "$T/good.zone"; yes ';cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' | head -c $((LIMIT - base + 1)); } > "$T/big_bad.zone"
STDIN_FILE=$T/big_ok.zone
jrun "stdin, exactly 64 MiB" 0 zone ex.test - && want "stdin: 64 MiB are checked" counts.checked 1
STDIN_FILE=$T/big_bad.zone
if jrun "stdin, 64 MiB and a byte" 1 zone ex.test -; then
    has "stdin: too large" io.stdin.too-large
fi
rm -f "$T/big_ok.zone" "$T/big_bad.zone"
: > "$T/empty.zone"
STDIN_FILE=$T/empty.zone
jrun "stdin, empty input" 1 zone ex.test - && has "stdin: an empty input is a syntax error, as an empty file is" zone.syntax
STDIN_FILE=
jrun "an empty file" 1 zone ex.test "$T/empty.zone" && has "an empty file is a syntax error" zone.syntax
# the text mode reads standard input as well
"$KC" zone ex.test - < "$T/good.zone" > "$T/o.txt" 2>&1; st=$?
if [ "$st" = 0 ] && grep -q "Zone 'ex.test.' is valid" "$T/o.txt"; then ok "text mode: zone ex.test - reads standard input"; else bad "text mode: stdin" "$(cat "$T/o.txt")"; fi

# ---------------------------------------------------------------- usage errors
echo "== usage errors"
jrun "no command" 2 && { has "usage: no command" usage.command.missing; want "usage: result" result usage; want "usage: command" command null; }
jrun "unknown command" 2 frobnicate && { has "usage: unknown command" usage.command.unknown; want "usage: the text names it" messages.0.text "unknown command 'frobnicate'"; }
jrun "zone without a domain" 2 zone && has "usage: zone needs a domain" usage.args
jrun "db with too many arguments" 2 db a b c && has "usage: db arguments" usage.args
for opt in -h --help -v --version; do
    "$KC" --json $opt < /dev/null > "$OUT" 2> "$ERR"; st=$?
    if [ "$st" = 2 ] && [ ! -s "$ERR" ] && $JC "$OUT" valid && $JC "$OUT" has usage.command.unknown; then ok "--json $opt is no command: a usage error in the document, nothing on stderr"; else bad "--json $opt (status $st)" "$(cat "$ERR"; head -c 600 "$OUT")"; fi
done
"$KC" > "$T/o.txt" 2>&1; st=$?
if [ "$st" = 2 ] && grep -q "^Usage:" "$T/o.txt"; then ok "text mode: the usage text on stderr, status 2"; else bad "text mode usage" "$(cat "$T/o.txt")"; fi
"$KC" -v > "$T/o.txt" 2>&1; st=$?
if [ "$st" = 0 ] && grep -q "^karicheck " "$T/o.txt"; then ok "text mode: -v still prints the version"; else bad "text mode -v" "$(cat "$T/o.txt")"; fi

# ---------------------------------------------------------------- hostile input
echo "== hostile names and texts"
# file names: a quote and a backslash, a line feed, bytes that are not UTF-8
for name in 'we"ird\name.zone' 'line
feed.zone' "$(printf 'bad\377\376name.zone')" "$(printf 'tab\there\001ctl.zone')"; do
    cp "$T/bad.zone" "$T/$name" 2>/dev/null || { bad "cannot make the file name $name"; continue; }
    if jrun "hostile file name" 1 zone bad.test "$T/$name"; then
        got=$($JC "$OUT" get messages.0.file)
        case "$got" in "$T/"*) ok "hostile file name: the document is valid and the name survives ($(printf '%s' "$name" | od -c | head -1 | cut -c9-40))";; *) bad "hostile file name: got '$got'";; esac
        has "hostile file name: still a syntax error" zone.syntax
    fi
    rm -f "$T/$name"
done
# a zone file named by a configuration, with a single quote and UTF-8 in its name (which is not there)
printf 'options { directory "%s"; };\nzone "ex.test" { type master; file "%s/it'"'"'s \303\274n\303\257c\303\266de\346\227\245.zone"; };\n' "$T" "$T" > "$T/hostile.conf"
jrun "a configuration with a zone file name in UTF-8" 1 zones "$T/hostile.conf" && has "hostile conf: the zone file is not there" io.open
# owner names with control characters and bytes above 127 (zone file escapes \DDD), in messages that quote the name
cat > "$T/ctl.zone" <<'EOF'
$ORIGIN ctl.test.
$TTL 300
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
a\001\255\"\\x IN CNAME b\255
b\255 IN CNAME www
www IN A 192.0.2.2
EOF
if jrun "owner names with control characters" 0 zone ctl.test "$T/ctl.zone"; then
    has "ctl names: the CNAME chain is reported" zone.cname.chain
fi
STDIN_FILE=$T/ctl.zone
jrun "the same on standard input" 0 zone ctl.test - && has "ctl names, stdin: the CNAME chain is reported" zone.cname.chain
STDIN_FILE=
# a zone name that is not a name; a very long one
jrun "a domain with quotes and a backslash" 1 zone 'a"b\c.test' "$T/good.zone"
jrun "a domain with a line feed" 1 zone 'a
b.test' "$T/good.zone"
jrun "an empty domain" 1 zone '' "$T/good.zone"
long=$(printf 'abcdefghij%.0s' $(seq 1 30))
jrun "a domain of 300 characters" 1 zone "$long.test" "$T/good.zone"
# a TXT record with bytes that are not UTF-8 and a long string: warnings that quote data
printf 'x IN TXT "caf\\233 \\001 %s"\n' "$(printf 'z%.0s' $(seq 1 300))" >> "$T/ctl.zone"
jrun "a long TXT string" 0 zone ctl.test "$T/ctl.zone" >/dev/null
# a configuration whose zone and view names are hostile
printf 'options { directory "%s"; };\nview "v\\"w\\\\x" { match-clients { any; }; zone "q\\"r.test" { type master; file "%s/good.zone"; }; };\n' "$T" "$T" > "$T/hostile2.conf"
jrun "a configuration with hostile view and zone names" 1 zones "$T/hostile2.conf" >/dev/null || true
printf 'options { directory "%s"; };\nzone "%s" { type master; file "%s/good.zone"; };\n' "$T" "$(printf 'bad\377name.test')" "$T" > "$T/hostile3.conf"
jrun "a configuration with a zone name that is not UTF-8" 1 zones "$T/hostile3.conf" >/dev/null || true
printf 'options { directory "%s"; no-such-%s yes; };\n' "$T" "$(printf 'op"t\001\377ion')" > "$T/hostile4.conf"
if jrun "a configuration with a hostile option name" 1 conf "$T/hostile4.conf"; then
    has "hostile option name: unknown option" conf.syntax
fi

# ---------------------------------------------------------------- the database
echo "== db"
if [ ! -x "$LOADER" ] || ! command -v sqlite3 >/dev/null 2>&1 || ! "$LOADER" --drivers 2>/dev/null | grep -qx sqlite3; then
    echo "  [SKIP] karidns-dbloader with the SQLite3 driver, or the sqlite3 tool, is not available"
else
    ME=$(id -un)
    if [ "$(id -u)" = "0" ]; then
        LUSER=${KARIDNS_TEST_LOADER_USER:-${SUDO_USER:-nobody}}
        if ! id "$LUSER" >/dev/null 2>&1 || [ "$LUSER" = root ]; then echo "  [SKIP] no unprivileged user to run the loader as"; LUSER=; fi
    else
        LUSER=$ME
    fi
    if [ -n "$LUSER" ]; then
        DBD=$T/dbd
        mkdir "$DBD"
        cp "$LOADER" "$DBD/dbl" && chmod 755 "$DBD/dbl"
        [ "$(id -u)" = "0" ] && { chown 0:0 "$DBD/dbl"; chown "$LUSER" "$DBD"; }
        chmod 755 "$DBD"
        DB=$DBD/z.db
        sqlite3 "$DB" < "$ROOT/tests/db/pdns_schema.sqlite3.sql" > /dev/null 2>&1
        sqlite3 "$DB" < "$ROOT/db/karidns_ext.sqlite3.sql" > /dev/null 2>&1
        sqlite3 "$DB" "PRAGMA journal_mode=WAL" > /dev/null 2>&1
        chmod 600 "$DB"
        sqlite3 "$DB" "
INSERT INTO domains (id, name, type) VALUES (1, 'ok.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
  (1, 'ok.test', 'SOA', 'ns1.ok.test hostmaster.ok.test 2024010101 3600 600 86400 300', 3600, NULL, '0'),
  (1, 'ok.test', 'NS', 'ns1.ok.test', 3600, NULL, '0'),
  (1, 'ns1.ok.test', 'A', '192.0.2.1', 3600, NULL, '0');
INSERT INTO domains (id, name, type) VALUES (2, 'bad.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
  (2, 'bad.test', 'SOA', 'ns1.bad.test hostmaster.bad.test 0 3600 600 86400 300', 3600, NULL, '0'),
  (2, 'bad.test', 'NS', 'ns1.bad.test', 3600, NULL, '0'),
  (2, 'ns1.bad.test', 'A', '192.0.2.1', 3600, NULL, '0'),
  (2, 'www.bad.test', 'CNAME', 'ns1.bad.test', 3600, NULL, '0'),
  (2, 'www.bad.test', 'A', '192.0.2.5', 3600, NULL, '0');
" > "$T/sql.out" 2>&1 || bad "the SQL of the database" "$(cat "$T/sql.out")"
        [ "$(id -u)" = "0" ] && chown "$LUSER" "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
        printf 'options {\n  user "%s";\n  database { driver sqlite3; database-file "%s"; loader-user "%s"; loader-path "%s/dbl"; acl-ceiling { 192.0.2.0/24; }; };\n};\n' \
            "$ME" "$DB" "$LUSER" "$DBD" > "$T/db.conf"
        if jrun "db" 1 db "$T/db.conf"; then
            want "db: command" command db
            want "db: result" result fail
            has "db: the database that is checked" db.checking
            has "db: the summary" db.summary
            has "db: a zone check of karicheck zone, with its code" zone.cname.coexists
            has "db: a finding of the loader" db.finding
            want "db: two zones were read" counts.checked 2
            want "db: two entries" zones.1.zone bad.test.
            want "db: format" zones.0.format database
            want "db: no file" zones.0.file null
            want "db: ok.test is fine" zones.0.result ok
            want "db: bad.test fails" zones.1.result fail
            zone_of_cname=$($JC "$OUT" get 'messages.*.zone' | grep -c '^bad.test.$')
            if [ "$zone_of_cname" -ge 2 ]; then ok "db: the findings of bad.test carry the zone"; else bad "db: findings with the zone bad.test: $zone_of_cname" "$(head -c 2000 "$OUT")"; fi
        fi
        jrun "db, one view that does not exist" 1 db nosuchview "$T/db.conf" && has "db: unknown view" db.view-not-found
        jrun "db, no database block" 1 db "$T/good.conf" && has "db: no database block" db.disabled
        # a loader that writes hostile findings (quotes, a backslash, control characters, bytes above 127, an unknown code)
        cat > "$DBD/fake" <<'EOFAKE'
#!/bin/sh
case "$1" in --drivers) echo sqlite3; exit 0;; esac
printf 'Z\tok.test.\t1\tprimary\t*\n'
printf 'E\tok.test.\t1\t"quoted" \\134 \\001 \\255 \\200\tzone.nothing.like.this\n'
printf 'W\tok.test.\t1\tsecond\tzone.ns.missing\n'
printf 'R\t1\t1\t1\n'
EOFAKE
        chmod 755 "$DBD/fake"
        [ "$(id -u)" = "0" ] && chown 0:0 "$DBD/fake"
        sed "s|$DBD/dbl|$DBD/fake|" "$T/db.conf" > "$T/dbfake.conf"
        if jrun "db, a loader with hostile findings" 1 db "$T/dbfake.conf"; then
            has "db: an unknown code from the loader is a db.finding" db.finding
            has "db: a known code from the loader is kept" zone.ns.missing
        fi
    fi
fi

echo
if [ "$FAILS" -eq 0 ]; then
    echo "=== run_karicheck_json_test: $PASS check(s) passed ==="
    exit 0
fi
echo "=== run_karicheck_json_test: $FAILS check(s) FAILED, $PASS passed ==="
exit 1

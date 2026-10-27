#!/bin/sh
# run_rdata_name_case_test.sh - the domain names inside RDATA keep the case of the zone data in answers and transfers
# (beta design D17-4; RFC 4343 s2-s4: a server preserves the case of names, the lower-case form is the DNSSEC canonical
# form of RFC 4034 s6.2 only).
#
# The names of MINFO MX CNAME PTR (RFC 1035 compression) are in domains of their own here: a compression pointer to a
# name of the same message that differs only in case shows the case of the earlier occurrence (RFC 4343 s4.1 allows
# that; an AXFR message compresses across records), the types written without compression keep their letters even
# where a suffix matches.
# Before B5, RP, AFSDB, RT, KX, PX, SRV (and others written without compression) and MINFO came out of a zone image in
# lower case, also for file zones, because serialize_dns_record() applied the canonical form.  One zone with mixed-case
# targets for MINFO RP AFSDB RT KX PX MX SRV NAPTR LP DNAME CNAME PTR is served from the zone file (server A) and, as root
# with sqlite3, from a SQLite3 database made by zone2sql (server B).  Checked:
#   - A answers every type with the exact letters of the zone file (UDP, dag text output, compression active where the
#     type allows it) and its AXFR carries them too;
#   - B's answers are byte for byte A's (dbquery, ID masked), so the DB path (reader, KDB1 stream, image) keeps the case as
#     well.  An AXFR of a DB zone is refused until B7 (allow-transfer of the metadata), so that part is the unit test
#     test_pdns_reader (file zone and DB zone serialize to the same bytes).
# Without root or sqlite3 only the file server is tested.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
. "$ROOT/tests/lib_proc.sh"

KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_rdcase.XXXXXX") || exit 1
chmod 755 "$T"
SA=""; SB=""
cleanup() {
    for p in $SA $SB; do kill -TERM "$p" 2>/dev/null; done
    sleep 0.3
    for p in $SA $SB; do kill -KILL "$p" 2>/dev/null; done
    if [ -n "${KARI_KEEP:-}" ]; then echo "kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((20000 + $$ % 20000))); PB=$((PA + 1))
USER_LINE=""
[ "$(id -u)" = "0" ] && USER_LINE='user "nobody";'

cat > "$T/case.test.zone" <<'EOF'
$ORIGIN case.test.
$TTL 300
@ IN SOA ns1 hostmaster 1 3600 600 86400 300
@ IN NS ns1
ns1 IN A 192.0.2.1
minfo IN MINFO RM.One.COM. EM.Two.ORG.
rp IN RP Mbox.Case.TEST. Txt.case.Test.
afsdb IN AFSDB 1 AFS.Case.test.
rt IN RT 10 Rt.Case.TEST.
kx IN KX 10 Kx.Case.TEST.
px IN PX 10 Map822.Case.test. MapX400.case.TEST.
mx IN MX 10 MAIL.Mx.NET.
srv IN SRV 1 2 5060 SIP.Case.Test.
naptr IN NAPTR 100 10 "S" "SIP+D2U" "" _SIP._udp.Case.Test.
lp IN LP 10 L.Case.TEST.
dn IN DNAME Target.Case.Test.
cn IN CNAME Cname.Cn.INFO.
ptr IN PTR Host.Ptr.BIZ.
EOF

# type -> a string of the text answer (dag text format) that has the letters as written in the zone
cat > "$T/expect.txt" <<'EOF'
minfo|MINFO|RM.One.COM. EM.Two.ORG.
rp|RP|Mbox.Case.TEST. Txt.case.Test.
afsdb|AFSDB|1 AFS.Case.test.
rt|RT|10 Rt.Case.TEST.
kx|KX|10 Kx.Case.TEST.
px|PX|10 Map822.Case.test. MapX400.case.TEST.
mx|MX|10 MAIL.Mx.NET.
srv|SRV|1 2 5060 SIP.Case.Test.
naptr|NAPTR|_SIP._udp.Case.Test.
lp|LP|10 L.Case.TEST.
dn|DNAME|Target.Case.Test.
cn|CNAME|Cname.Cn.INFO.
ptr|PTR|Host.Ptr.BIZ.
EOF

printf 'options {\n    %s pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n};\nzone "case.test" { type primary; file "%s/case.test.zone"; allow-transfer { 127.0.0.1; }; };\n' "$USER_LINE" "$PA" "$T" > "$T/a.conf"
"$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 &
SA=$!
i=0
while [ $i -lt 50 ]; do ./dag @127.0.0.1 -p "$PA" case.test SOA +short +nohexdump +time=1 +tries=1 > /dev/null 2>&1 && break; sleep 0.2; i=$((i + 1)); done

echo "== file zone: UDP answers"
while IFS='|' read -r owner type want; do
    got=$(./dag @127.0.0.1 -p "$PA" "$owner.case.test" "$type" +noall +answer +nohexdump 2>/dev/null | awk -v t="$type" '$4 == t { sub(/^[^ \t]+[ \t]+[0-9]+[ \t]+IN[ \t]+[A-Z0-9]+[ \t]+/, ""); print; exit }')
    case "$got" in *"$want"*) pass "$type answered as written: $got" ;; *) fail "$type: expected '$want' in '$got'" ;; esac
done < "$T/expect.txt"

echo "== file zone: AXFR"
./dag @127.0.0.1 -p "$PA" case.test AXFR +noall +answer +nohexdump 2>/dev/null > "$T/axfr.txt"
while IFS='|' read -r owner type want; do
    if awk -v t="$type" -v o="$owner.case.test." '$1 == o && $4 == t' "$T/axfr.txt" | grep -qF -- "$want"; then pass "AXFR $type as written"
    else fail "AXFR $type: '$want' not found ($(awk -v t="$type" -v o="$owner.case.test." '$1 == o && $4 == t' "$T/axfr.txt" | head -1))"; fi
done < "$T/expect.txt"

echo "== database zone"
if [ "$(id -u)" != "0" ] || ! command -v sqlite3 >/dev/null 2>&1 || ! command -v cc >/dev/null 2>&1 || [ ! -x ./karidns-dbloader ] || [ ! -x ./tests/db/zone2sql ] ||
   ! id nobody >/dev/null 2>&1 || ! ./karidns-dbloader --drivers 2>/dev/null | grep -qx sqlite3; then
    echo "  [SKIP] the database part needs root, sqlite3, cc, karidns-dbloader (SQLite3 driver), tests/db/zone2sql and the user nobody"
else
    cc -O1 -o "$T/dbquery" tests/db/dbquery.c 2> "$T/cc.log" || { echo "  [SKIP] dbquery does not compile"; cat "$T/cc.log"; }
    if [ -x "$T/dbquery" ]; then
        mkdir "$T/db"
        sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
        ./tests/db/zone2sql --dialect sqlite3 "$T/case.test.zone" | sqlite3 "$T/db/z.db" > /dev/null 2>&1 || fail "zone2sql / import"
        chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
        install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
        printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n    database { driver sqlite3; database-file "%s/db/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; };\n};\n' "$PB" "$T" "$T" > "$T/b.conf"
        "$KARIDNS" -c "$T/b.conf" -f > "$T/b.log" 2>&1 &
        SB=$!
        i=0
        while [ $i -lt 300 ]; do grep -q "initial load complete" "$T/b.log" 2>/dev/null && break; sleep 0.1; i=$((i + 1)); done
        sleep 0.3
        : > "$T/q.list"
        while IFS='|' read -r owner type want; do
            printf '%s.case.test. %s p\n%s.case.test. %s e\n%s.case.test. %s d\n' "$owner" "$type" "$owner" "$type" "$owner" "$type" >> "$T/q.list"
        done < "$T/expect.txt"
        printf 'case.test. ANY e\nfoo.dn.case.test. A e\nfoo.dn.case.test. CNAME e\nfoo.cn.case.test. A e\n' >> "$T/q.list"
        "$T/dbquery" -p "$PA" -t 3 "$T/q.list" "$T/q.a" > /dev/null 2>&1
        "$T/dbquery" -p "$PB" -t 3 "$T/q.list" "$T/q.b" > /dev/null 2>&1
        NQ=$(wc -l < "$T/q.list" | tr -d ' ')
        diffs=$(awk -F'\t' 'FILENAME == ARGV[1] { s[FNR] = $2; next } { n++; if ($2 != s[FNR] || $2 == "TIMEOUT") bad++ } END { printf "%d %d\n", n, bad }' "$T/q.a" "$T/q.b")
        set -- $diffs
        if [ "$1" = "$NQ" ] && [ "$2" = "0" ]; then pass "database zone: $NQ queries byte-identical to the file zone"; else fail "database zone: $2 of $1 queries differ from the file zone"; fi
        # the DB server did serve the zone with the letters as written (not only "the same as the file server")
        got=$(./dag @127.0.0.1 -p "$PB" rp.case.test RP +noall +answer +nohexdump 2>/dev/null | grep -F -- "Mbox.Case.TEST. Txt.case.Test." | head -1)
        if [ -n "$got" ]; then pass "database zone: RP answered as written"; else fail "database zone: RP not answered as written"; fi
    fi
fi
if grep -q "AddressSanitizer\|runtime error:" "$T/a.log" "$T/b.log" 2>/dev/null; then fail "sanitizer report in a server log"; fi
if [ "$FAILS" -eq 0 ]; then echo "=== run_rdata_name_case_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_rdata_name_case_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

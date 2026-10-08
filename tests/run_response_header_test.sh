#!/bin/sh
# Response header bits and error responses (AUDIT_FINDINGS R-05, R-06, R-12, R-13, R-18, R-27 addendum).
# - RFC 1035 §4.1.1 / RFC 4035 §3.1.6: RA, Z, AD and TC of the query are never copied into the response;
#   CD and RD are echoed. AA only on answers from an authoritative zone and on an accepted NOTIFY (RFC 1996 §4.7).
# - REFUSED (not authoritative), SERVFAIL (zone not loaded, zone expired) and refused NOTIFY have AA=0.
# - RFC 6891 §7: a malformed option (ECS, RFC 7871 §6) is answered FORMERR with an OPT record.
# - NOTIFY/UPDATE to a forward zone: NOTIMP with the question section only (no request bytes left behind).
# - RFC 8914: expired secondary -> SERVFAIL with EDE 24 (Invalid Data), not EDE 3 (Stale Answer).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PPORT=15491
SPORT=15492
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-rhdr.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
PRIMARY_PID=""
SECONDARY_PID=""

cleanup() {
    kari_kill_tree "$PRIMARY_PID" "$SECONDARY_PID"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    for f in "$W"/out.txt "$W"/primary.log "$W"/secondary.log; do
        [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }
    done
    exit 1
}

check_asan_log() {
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$W/primary.log" "$W/secondary.log"; then
        fail "sanitizer report in a server log"
    fi
}

# SOA: refresh 1, retry 1, expire 5 so that the secondary expires quickly once the primary is gone.
cat > "$W/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 1 1 5 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
EOF

# Program zone plugin (its "oversized" name returns a ~2 KB TXT answer), copied so that it is executable.
cp "$DIR/plugins/dnstestscript.pl" "$W/plugin.pl"
chmod 755 "$W/plugin.pl"

cat > "$W/primary.conf" <<EOF
options { port $PPORT; bind-address { 127.0.0.1; }; pid-file "none"; send-extended-errors yes;
          ecs-enable yes; ecs-trusted-resolvers { 127.0.0.1; }; allow-program-zones yes; $USER_OPT };
zone "example.test" { type master; file "$W/example.test.zone"; allow-transfer { 127.0.0.1; }; };
zone "fwd.test" { type forward; forwarders { 127.0.0.1 port 9; }; };
zone "empty.test" { type slave; masters { 127.0.0.1 port 9; }; };
zone "prog.test" { type program; program "$W/plugin.pl"; };
EOF

cat > "$W/secondary.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; send-extended-errors yes; serve-stale no; $USER_OPT };
zone "example.test" { type slave; masters { 127.0.0.1 port $PPORT; }; };
EOF

"$BIN" -f "$W/primary.conf" > "$W/primary.log" 2>&1 &
PRIMARY_PID=$!
"$BIN" -f "$W/secondary.conf" > "$W/secondary.log" 2>&1 &
SECONDARY_PID=$!

q() { # q PORT ARGS... -> full dag output in out.txt
    port=$1; shift
    "$DAG" @127.0.0.1 -p "$port" +nohexdump "$@" > "$W/out.txt" 2>&1 || true
}
flags_line() { grep -m1 '^;; flags:' "$W/out.txt" | sed 's/^;; flags: //; s/;.*//; s/ *$//'; }
expect_status() { grep -q "status: $1," "$W/out.txt" || fail "$2: expected status $1"; }
expect_flags() { [ "$(flags_line)" = "$1" ] || fail "$2: flags '$(flags_line)', expected '$1'"; }
expect_opt() { grep -q "OPT PSEUDOSECTION" "$W/out.txt" || fail "$1: no OPT in the response"; }
no_extra() {
    if grep -qiE "extra bytes|malformed" "$W/out.txt"; then fail "$1: trailing bytes in the response"; fi
}

i=0
while ! "$DAG" example.test SOA @127.0.0.1 -p $SPORT +short +nohexdump 2>/dev/null | grep -q hostmaster; do
    i=$((i + 1))
    [ $i -le 40 ] || fail "secondary did not transfer example.test"
    sleep 0.5
done

# 1. R-05: RA/Z/AD/TC are not echoed; RD and CD are.
q $PPORT www.example.test A +raflag +zflag +adflag +cdflag +tcflag
expect_status NOERROR "answer"
expect_flags "qr aa rd cd" "answer with RA/Z/AD/CD/TC set in the query"
grep -q "MBZ" "$W/out.txt" && fail "answer: Z bit copied"
q $PPORT www.example.test A +norecurse
expect_flags "qr aa" "answer without RD"
echo "[OK] R-05 answer header"

# 2. R-06: REFUSED for a zone the server does not serve: AA=0, EDE 20.
q $PPORT nosuch.invalid A +adflag
expect_status REFUSED "not authoritative"
expect_flags "qr rd" "REFUSED"
grep -q "EDE: 20" "$W/out.txt" || fail "REFUSED: expected EDE 20"
echo "[OK] R-06 REFUSED without AA"

# 3. R-13: malformed ECS (SCOPE != 0, FAMILY 3) -> FORMERR with OPT and the question.
for opt in 8:00011810c00002 8:00031800c00002; do
    q $PPORT www.example.test A +ednsopt=$opt
    expect_status FORMERR "ECS $opt"
    expect_opt "ECS $opt"
    grep -q "QUERY: 1," "$W/out.txt" || fail "ECS $opt: question not kept"
done
echo "[OK] R-13 FORMERR with OPT for malformed ECS"

# 4. R-27 addendum: secondary that never loaded -> SERVFAIL, EDE 14, AA=0.
q $PPORT empty.test SOA
expect_status SERVFAIL "zone not ready"
expect_flags "qr rd" "zone not ready"
grep -q "EDE: 14" "$W/out.txt" || fail "zone not ready: expected EDE 14"
echo "[OK] R-27 zone not ready without AA"

# 5. NOTIFY: accepted (from the configured master) -> QR AA; refused -> AA=0.
q $SPORT example.test SOA +opcode=notify +norecurse
expect_status NOERROR "NOTIFY from the master"
expect_flags "qr aa" "accepted NOTIFY"
q $PPORT example.test SOA +opcode=notify +norecurse
expect_status REFUSED "NOTIFY to a primary"
expect_flags "qr" "refused NOTIFY"
echo "[OK] NOTIFY AA only when accepted"

# 6. R-12: UPDATE / NOTIFY to a forward zone -> NOTIMP, question only, no request bytes echoed.
q $PPORT fwd.test --update-add "a.fwd.test 300 IN A 192.0.2.5"
expect_status NOTIMP "UPDATE to a forward zone"
no_extra "UPDATE to a forward zone"
grep -q "ANSWER: 0, AUTHORITY: 0" "$W/out.txt" || fail "UPDATE to a forward zone: sections not empty"
q $PPORT fwd.test SOA +opcode=notify +norecurse
expect_status NOTIMP "NOTIFY to a forward zone"
no_extra "NOTIFY to a forward zone"
echo "[OK] R-12 NOTIMP for forward zones"

# 7. Unknown opcode: NOTIMP, EDE 21, AD not echoed.
q $PPORT example.test SOA +opcode=2 +adflag
expect_status NOTIMP "opcode 2"
expect_flags "qr rd" "opcode 2"
grep -q "EDE: 21" "$W/out.txt" || fail "opcode 2: expected EDE 21"
echo "[OK] unknown opcode"

# 8. UDP limit = the client's EDNS size, also when it is exactly 512 (program/forward zones are answered on the
#    async path, which used to allow 4096 bytes). The ~2 KB plugin answer must come back truncated (TC=1).
for b in 512 1232; do
    q $PPORT oversized.prog.test TXT +bufsize=$b +ignore
    grep -q "^;; flags: qr aa tc;" "$W/out.txt" || fail "program zone, EDNS $b: expected a TC=1 reply"
    size=$(sed -n 's/^;; MSG SIZE *rcvd: *//p' "$W/out.txt")
    [ -n "$size" ] && [ "$size" -le "$b" ] || fail "program zone, EDNS $b: reply of $size bytes"
done
echo "[OK] UDP reply limited to the EDNS size (512 and 1232)"

# 9. R-18: stop the primary; after SOA EXPIRE (5 s) the secondary answers SERVFAIL with EDE 24, AA=0.
kari_kill_tree "$PRIMARY_PID"
PRIMARY_PID=""
i=0
while :; do
    q $SPORT www.example.test A
    grep -q "status: SERVFAIL," "$W/out.txt" && break
    i=$((i + 1))
    [ $i -le 30 ] || fail "secondary did not expire example.test"
    sleep 1
done
expect_flags "qr rd" "expired zone"
grep -q "EDE: 24" "$W/out.txt" || fail "expired zone: expected EDE 24 (Invalid Data)"
grep -q "EDE: 3 " "$W/out.txt" && fail "expired zone: EDE 3 (Stale Answer) on SERVFAIL"
echo "[OK] R-18 expired secondary: SERVFAIL, EDE 24"

check_asan_log
kill -0 "$SECONDARY_PID" 2>/dev/null || fail "secondary exited"
echo "[PASS] response header bits and error responses"
exit 0

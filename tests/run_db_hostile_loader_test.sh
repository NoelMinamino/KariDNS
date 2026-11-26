#!/bin/sh
# run_db_hostile_loader_test.sh - a loader that sends bad zone data (beta design 1.4, 1.5, 8.4; milestone B4b).
#
# tests/db/fake_dbloader.c (./fake_dbloader, make fake_dbloader) stands in for karidns-dbloader on the stream and sends one batch: ok1.test, a
# bad zone (bad.test), ok2.test.  The data of a zone is a zone image (0.7 M3).  Two kinds of mistakes:
#   - an image that fails the checks of the Backend (zone_image_validate_ex(): an owner outside the zone, an SOA that is not at the
#     apex, two SOAs without the extended flag, the image of another zone, a class other than IN, a serial that is not the one ZONE_BEGIN
#     declared, the tinydns flag, noise inside the image), a secondary or extended zone: only that zone is rejected (ZONE_RESULT "rejected"),
#     the stream stays open, the zones around it are installed and answer, the bad zone does not exist (REFUSED), `karictl dbstatus` names the reason;
#   - a stream that breaks the protocol (an oversize frame, ZONE_END with another count, a count the header of the image does not carry, a
#     message of the old type ZONE_DATA, a zone that is not an image, a HELLO without the image feature or with another image version, an image
#     that is shorter or longer than announced, a damaged header, an unknown TLV tag): one protocol-error line, the stream is
#     closed, the supervisor restarts the loader, the partial zone is thrown away, the zones before it answer.
# In every case the Backend survives and keeps answering the file zone.  KARIDNS=./karidns-asan runs it on the ASan build.
#
# Needs root (the loader must be root-owned and runs as nobody).  SKIP otherwise, and when a binary or a compiler is
# missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
[ -x ./fake_dbloader ] || { echo "SKIP: ./fake_dbloader is not built (make fake_dbloader)"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbhostile.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    # wait for the manager (it stops its children first; a sanitizer build is slow): a KILL too early orphans them
    i=0; while [ -n "$SRV" ] && [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
DAG="./dag @127.0.0.1 -p $PORT"
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

cp ./fake_dbloader "$T/fake_dbloader"
chown 0:0 "$T/fake_dbloader"; chmod 755 "$T/fake_dbloader"
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n' > "$T/file.zone"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf FILE LOADERPATH
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/none.db"; loader-user "nobody"; loader-path "$2"; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
zone "file.test" { type primary; file "$T/file.zone"; };
EOF
}
wait_log() {   # wait_log LOG PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -Eq -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
ans() { $DAG "$@" +short +nohexdump 2>/dev/null; }
wait_ans() {   # wait_ans EXPECTED QNAME QTYPE: answers within 5 s
    i=0
    while [ $i -lt 50 ]; do
        [ "$(ans "$2" "$3")" = "$1" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
refused() { $DAG "$1" SOA +nohexdump 2>/dev/null | grep -q "status: REFUSED"; }
file_answers() { [ "$(ans www.file.test A)" = "192.0.2.80" ]; }

# run MODE KIND PATTERN [BATCH-LINE-PATTERN]
#   KIND reject: the zone bad.test is rejected for a reason matching PATTERN, the stream stays open
#   KIND error:  the stream breaks the protocol, PATTERN is the reason in the log
#   KIND ok:     nothing is wrong (PATTERN is the batch line)
run_mode() {
    mode=$1; kind=$2; pat=$3; bpat=${4:-}
    echo "== $mode"
    printf '#!/bin/sh\nexec "%s/fake_dbloader" -s 3 %s\n' "$T" "$mode" > "$T/fake_$mode"
    chown 0:0 "$T/fake_$mode"; chmod 755 "$T/fake_$mode"
    conf "$T/$mode.conf" "$T/fake_$mode"
    "$KARIDNS" -c "$T/$mode.conf" -f > "$T/$mode.log" 2>&1 &
    SRV=$!
    L="$T/$mode.log"
    case $kind in
    reject|ok)
        if wait_log "$L" "\[DB\] batch 1 complete" 15; then pass "$mode: the batch completed"; else fail "$mode: no 'batch 1 complete'"; sed 's/^/         /' "$L" | tail -12; fi
        [ -n "$bpat" ] && { grep -q -- "$bpat" "$L" && pass "$mode: batch line matches '$bpat'" || { fail "$mode: batch line"; grep "batch 1 complete" "$L" | sed 's/^/         /'; }; }
        ! grep -q "protocol error" "$L" && pass "$mode: no protocol error" || fail "$mode: protocol error logged"
        [ "$(grep -c 'Restarting the database loader' "$L")" -eq 0 ] && pass "$mode: the loader was not restarted" || fail "$mode: the loader was restarted"
        wait_ans 192.0.2.10 www.ok1.test A && pass "$mode: www.ok1.test answers" || fail "$mode: www.ok1.test does not answer"
        wait_ans 192.0.2.25 mail.ok2.test A && pass "$mode: mail.ok2.test (after the bad zone) answers" || fail "$mode: mail.ok2.test does not answer"
        if [ "$kind" = reject ]; then
            grep -Eq "zone 'bad.test.' \(view '[_a-z]*'\) rejected: .*($pat)" "$L" && pass "$mode: bad.test rejected: $pat" || { fail "$mode: no rejection with '$pat'"; grep "rejected" "$L" | sed 's/^/         /'; }
            refused bad.test && pass "$mode: bad.test does not exist (REFUSED)" || fail "$mode: bad.test answers"
            $KCTL dbstatus bad.test 2>&1 | grep -Eq "status rejected \(no version loaded\), last error: .*($pat)" && pass "$mode: dbstatus names the reason" || { fail "$mode: dbstatus"; $KCTL dbstatus bad.test 2>&1 | sed 's/^/         /'; }
            $KCTL dbstatus 2>&1 | grep -q "^last batch: id 1, kind startup, finished .*: 2 applied, 1 rejected" && pass "$mode: dbstatus: 2 applied, 1 rejected" || fail "$mode: dbstatus summary"
        fi
        ;;
    error)
        if wait_log "$L" "protocol error from the loader: .*($pat)" 15; then pass "$mode: protocol error '$pat'"; else fail "$mode: no protocol error with '$pat'"; sed 's/^/         /' "$L" | tail -12; fi
        sleep 0.3
        [ "$(grep -c 'protocol error from the loader' "$L")" -eq 1 ] && pass "$mode: logged once" || fail "$mode: logged $(grep -c 'protocol error from the loader' "$L") times"
        grep "protocol error from the loader" "$L" | head -1 | grep -q "closing the stream" && pass "$mode: the stream is closed" || fail "$mode: no 'closing the stream'"
        wait_log "$L" "Database loader .* started .*restart" 10 && pass "$mode: the supervisor restarted the loader" || fail "$mode: no restart"
        refused bad.test && pass "$mode: the partial zone was thrown away (bad.test REFUSED)" || fail "$mode: bad.test answers"
        wait_ans 192.0.2.10 www.ok1.test A && pass "$mode: ok1.test (completed before the error) answers" || fail "$mode: ok1.test does not answer"
        $KCTL dbstatus 2>&1 | grep -Eq "^last protocol error: .*($pat)" && pass "$mode: dbstatus shows the protocol error" || { fail "$mode: dbstatus protocol error"; $KCTL dbstatus 2>&1 | sed 's/^/         /'; }
        ;;
    esac
    if [ "$mode" = settings-ok ]; then   # the zone took the profile and its own statements
        OUT=$($KCTL dbstatus bad.test 2>&1)
        if printf '%s\n' "$OUT" | grep -q "settings: profile 'p1'" && printf '%s\n' "$OUT" | grep -q "allow-transfer: addresses 127.0.0.1 (match all)"; then
            pass "$mode: dbstatus shows the profile and the zone's ACL"
        else
            fail "$mode: dbstatus bad.test"; printf '%s\n' "$OUT" | sed 's/^/         /'
        fi
    fi
    file_answers && pass "$mode: the Backend survived and answers the file zone" || fail "$mode: the file zone does not answer"
    kill -TERM "$SRV"
    i=0; while [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -0 "$SRV" 2>/dev/null && fail "$mode: karidns did not stop"
    SRV=""
    sleep 0.3
}

# a long batch: the first zone must be visible before the batch ends (the view delta runs at least once a second)
echo "== slow"
mode=slow
printf '#!/bin/sh
exec "%s/fake_dbloader" -s 3 slow
' "$T" > "$T/fake_slow"
chown 0:0 "$T/fake_slow"; chmod 755 "$T/fake_slow"
conf "$T/slow.conf" "$T/fake_slow"
"$KARIDNS" -c "$T/slow.conf" -f > "$T/slow.log" 2>&1 &
SRV=$!
i=0; while [ $i -lt 40 ] && [ "$(ans www.ok1.test A)" != "192.0.2.10" ]; do sleep 0.1; i=$((i + 1)); done
if [ "$(ans www.ok1.test A)" = "192.0.2.10" ]; then pass "slow: www.ok1.test answers after about $((i / 10)) s, during the batch"; else fail "slow: www.ok1.test does not answer during the batch"; fi
! grep -q "batch 1 complete" "$T/slow.log" && pass "slow: the batch is still open at that point" || fail "slow: the batch was already complete (the test proves nothing)"
[ "$(ans mail.ok2.test A)" != "192.0.2.25" ] && pass "slow: ok2.test, not sent yet, does not answer" || fail "slow: ok2.test answers before it was sent"
wait_log "$T/slow.log" "\[DB\] batch 1 complete: 2 zone" 15 && pass "slow: the batch completes" || fail "slow: no batch end"
wait_ans 192.0.2.25 mail.ok2.test A && pass "slow: ok2.test answers after the batch" || fail "slow: ok2.test does not answer"
kill -TERM "$SRV"
i=0; while [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
SRV=""
sleep 0.3

run_mode good ok "" "batch 1 complete: 2 zone(s) received (2 installed, 0 hidden by karidns.conf, 0 rejected)"
run_mode again ok "" "batch 1 complete: 3 zone(s) received (3 installed"
# 0.7 M3: the zone is an image; what the Backend checked while it built the zone from RRs is checked on the image (zone_image_validate_ex())
run_mode owner-outside reject "outside the zone" "batch 1 complete: 3 zone(s) received (2 installed, 0 hidden by karidns.conf, 1 rejected)"
run_mode soa-subdomain reject "SOA outside the apex"
run_mode two-soa reject "several SOA records"
run_mode other-zone reject "outside the zone|no data at the apex"
run_mode non-in-class reject "class 3"
run_mode image-serial reject "not the one ZONE_BEGIN declared"
run_mode image-tinydns reject "tinydns flag"
run_mode nsec3-iter reject "NSEC3 iterations"
run_mode ecs-trusted reject "ECS trusted"
run_mode image-garbage reject "the zone image is refused"
# B7b: SLAVE / CONSUMER zones carry no data; a secondary needs masters, and its rr_count is 0 (a ZONE_IMAGE after it is a protocol error)
run_mode secondary-kind reject "needs masters in its settings"
run_mode secondary-data error "a secondary zone has rr_count 0"
run_mode secondary-flag reject "carries no zone flags"
run_mode secondary-host reject "masters has an entry that is not an IP address"
run_mode secondary-prim reject "settings of a primary zone name masters"
run_mode secondary-ok ok "" "batch 1 complete: 3 zone(s) received (3 installed"
run_mode catalog-ok ok "" "batch 1 complete: 3 zone(s) received (3 installed"
run_mode ext-flag-bit error "value out of range|flags"
run_mode ext-image-flag error "image size"
run_mode ext-ok ok "" "batch 1 complete: 3 zone(s) received (3 installed"
run_mode delete-unknown ok "" "batch 1 complete: 2 zone(s) received (2 installed"
run_mode huge-frame error "above the limit"
run_mode end-count error "count differs from ZONE_BEGIN"
run_mode begin-count error "the RR count in the header differs from ZONE_BEGIN"
run_mode unknown-tag error "unknown tag 99"
run_mode zone-data error "unknown message type 5"
run_mode no-image-flag error "the data of a primary zone is a zone image"
run_mode image-magic error "not the header of an image of this version"
run_mode image-size-hdr error "the size in the header differs from ZONE_BEGIN"
run_mode image-short error "the image is not complete"
run_mode image-extra error "more octets than ZONE_BEGIN announced"

# B7a: the settings text and the PROFILE messages are as hostile as the zone data
run_mode settings-ok ok "" "batch 1 complete: 3 zone(s) received (3 installed"
run_mode settings-key reject "TSIG key 'ghost'" "batch 1 complete: 3 zone(s) received (2 installed, 0 hidden by karidns.conf, 1 rejected)"
run_mode settings-include reject "'include' is not allowed"
run_mode settings-file reject "statement 'file' is not allowed"
run_mode settings-slave reject "statement 'type' is not allowed"
run_mode settings-brace reject "unbalanced braces"
run_mode profile-missing reject "profile 'p1' is not defined"
run_mode profile-flood error "more profile data in a batch"

# the unknown delete is answered "unchanged" and logged
if grep -q "delete of zone 'nothere.test.' (view 0, id 4242) ignored" "$T/delete-unknown.log"; then pass "delete-unknown: the delete of an unregistered zone is ignored and logged"; else fail "delete-unknown: no 'ignored' line"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_hostile_loader_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_hostile_loader_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1

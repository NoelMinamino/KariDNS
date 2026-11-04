#!/bin/sh
# ==============================================================================
# tests/run_karictl_rollback_test.sh - karictl rollback <zone> [view] [local]
# ==============================================================================
# A primary (zone files) and a secondary that follows rb.test.
#   1. karicheck: rollback-window is read (also per zone), a bad value is an error with file:line
#   2. nothing to go back to: no previous version; a window of 0 keeps none; a secondary zone, an unknown zone, no zone name
#   3. reload with bad data -> rollback: the old data is served again with SOA serial = bad serial + 1; zonestatus says
#      "rolled back (serial N, from M)"; the secondary follows (IXFR from the difference, NOTIFY) and serves the old data
#   4. a second rollback is refused (no redo); status shows the bytes kept; the previous version is counted
#   5. the file did not change: reload <zone> and a full reload keep the rolled-back version; reload <zone> force reads the file again
#   6. a signed zone: refused ("zone is signed"); with `local` the old version, with its old serial, is served on this server only
#   7. the window: rollback-window 2 on a zone -> the tick drops the previous version, rollback is refused afterwards
#   8. keys: a read-only key with allow-commands { reload-zone; } is refused (ERROR command not allowed), a key with
#      allow-commands { rollback; } may roll back; the command is logged with the key name
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
. "${SCRIPT_DIR}/lib_proc.sh"
cd "${ROOT_DIR}"

KARIDNS="${KARIDNS:-${ROOT_DIR}/karidns}"
KARICTL="${KARICTL:-${ROOT_DIR}/karictl}"
KARICHECK="${KARICHECK:-${ROOT_DIR}/karicheck}"
DAG="${DAG:-${ROOT_DIR}/dag}"
[ -x "${KARIDNS}" ] && [ -x "${KARICTL}" ] && [ -x "${KARICHECK}" ] && [ -x "${DAG}" ] || make karidns karictl karicheck dag >/dev/null || exit 1
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl is needed to make the test secrets"; exit 0; }

TMP_DIR="$(mktemp -d /tmp/karidns_rollback.XXXXXX)"
chmod 755 "${TMP_DIR}"
SOCK="${TMP_DIR}/control.sock"
PLOG="${TMP_DIR}/primary.log"
SLOG="${TMP_DIR}/secondary.log"
PRI_PID=""
SEC_PID=""
FAILED=0

cleanup() {
    set +e
    [ -n "${PRI_PID}" ] && kari_kill_tree "${PRI_PID}"
    [ -n "${SEC_PID}" ] && kari_kill_tree "${SEC_PID}"
    kari_kill_conf "${TMP_DIR}/primary.conf" "${TMP_DIR}/secondary.conf"
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

PORT=$(kari_port 0 $((27000 + $$ % 2000)))
SPORT=$(kari_port 1 $((PORT + 1)))
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

b64() { printf '%s' "$1" | openssl base64 -A; }
MAIN_SECRET=$(b64 "rb-test-main-secret-0123456789abc")
WEB_SECRET=$(b64 "rb-test-web-secret-0123456789abcd")
RBK_SECRET=$(b64 "rb-test-rbk-secret-0123456789abcd")

# wz FILE ZONE SERIAL WWW [EXTRA...] : a zone file (refresh 2 s so that the secondary follows quickly)
wz() {
    _f="${TMP_DIR}/$1"; _z=$2; _s=$3; _w=$4; shift 4
    {
        printf '$ORIGIN %s.\n$TTL 60\n@ IN SOA ns hostmaster %s 2 1 3600 60\n@ IN NS ns\nns IN A 192.0.2.1\nwww IN A %s\n' "${_z}" "${_s}" "${_w}"
        for _x in "$@"; do printf '%s\n' "${_x}"; done
    } > "${_f}"
    chmod 644 "${_f}"
}
DNSKEY='@ IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=='
wz rb.zone rb.test 1 192.0.2.10
wz off.zone off.test 1 192.0.2.10
wz sig.zone sig.test 1 192.0.2.10 "${DNSKEY}"
wz exp.zone exp.test 1 192.0.2.10

write_primary() {
    cat > "${TMP_DIR}/primary.conf" <<EOF
options { port ${PORT}; bind-address { 127.0.0.1; }; pid-file "none"; ${USER_OPT} };
key "web" { algorithm hmac-sha256; secret "${WEB_SECRET}"; };
key "rbk" { algorithm hmac-sha256; secret "${RBK_SECRET}"; };
control-channel {
    socket "${SOCK}";
    secret "${MAIN_SECRET}";
    keys {
        "web" read-only yes allow-commands { reload-zone; };
        "rbk" read-only yes allow-commands { rollback; };
    };
};
zone "rb.test" { type master; file "${TMP_DIR}/rb.zone"; allow-transfer { 127.0.0.1; }; also-notify { 127.0.0.1 port ${SPORT}; }; };
zone "off.test" { type master; file "${TMP_DIR}/off.zone"; rollback-window 0; };
zone "sig.test" { type master; file "${TMP_DIR}/sig.zone"; };
zone "exp.test" { type master; file "${TMP_DIR}/exp.zone"; rollback-window 2; };
zone "sec.test" { type secondary; primaries { 127.0.0.1 port 1; }; };
${1:-}
EOF
    chmod 644 "${TMP_DIR}/primary.conf"
}
write_primary
cat > "${TMP_DIR}/secondary.conf" <<EOF
options { port ${SPORT}; bind-address { 127.0.0.1; }; pid-file "none"; ${USER_OPT} };
zone "rb.test" { type slave; masters { 127.0.0.1 port ${PORT}; }; };
EOF
chmod 644 "${TMP_DIR}/secondary.conf"

ctl_conf() { # FILE SECRET
    printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "${SOCK}" "$2" > "$1"
    chmod 600 "$1"
}
ctl_conf "${TMP_DIR}/main.conf" "${MAIN_SECRET}"
ctl_conf "${TMP_DIR}/web.conf" "${WEB_SECRET}"
ctl_conf "${TMP_DIR}/rbk.conf" "${RBK_SECRET}"

# ctl KEY args... : sets OUT and RC
ctl() { _c="${TMP_DIR}/$1.conf"; shift; OUT=$("${KARICTL}" -c "${_c}" -s "${SOCK}" "$@" 2>&1); RC=$?; }
expect() { # LABEL RC REGEX
    if [ "${RC}" -ne "$2" ]; then fail "$1: exit ${RC}, expected $2: ${OUT}"
    elif [ -n "$3" ] && ! printf '%s\n' "${OUT}" | grep -E -q "$3"; then fail "$1: output does not match '$3': ${OUT}"
    else pass "$1"; fi
}
www() { "${DAG}" @127.0.0.1 -p "$1" "www.$2" A +short +nohexdump +norec +timeout=2 +tries=1 2>/dev/null; }
serial() { "${DAG}" @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump +norec +timeout=2 +tries=1 2>/dev/null | awk '{print $3}'; }
wait_for() { # SECONDS command...  : the command succeeds within SECONDS
    _n=$(($1 * 5)); shift
    while [ "${_n}" -gt 0 ]; do "$@" && return 0; sleep 0.2; _n=$((_n - 1)); done
    return 1
}
sec_is() { [ "$(serial "${SPORT}" rb.test)" = "$1" ] && [ "$(www "${SPORT}" rb.test)" = "$2" ]; }

# ---------------------------------------------------------------------------------------------------------------
echo "=== 1. karicheck ==="
out=$("${KARICHECK}" conf "${TMP_DIR}/primary.conf" 2>&1); rc=$?
[ "${rc}" -eq 0 ] && pass "rollback-window (options and zone) is accepted" || fail "karicheck: rc=${rc}: ${out}"
printf 'options { rollback-window soon; };\n' > "${TMP_DIR}/bad.conf"
out=$("${KARICHECK}" conf "${TMP_DIR}/bad.conf" 2>&1); rc=$?
[ "${rc}" -ne 0 ] && printf '%s\n' "${out}" | grep -E -q "bad.conf:[0-9]+: .*rollback-window: invalid value 'soon'" && pass "a bad rollback-window is an error with file:line" || fail "bad value: rc=${rc}: ${out}"
printf 'options { rollback-window 90m; }; zone "z.test" { type master; file "z"; rollback-window 0; };\n' > "${TMP_DIR}/ok2.conf"
out=$("${KARICHECK}" conf "${TMP_DIR}/ok2.conf" 2>&1); rc=$?
[ "${rc}" -eq 0 ] && pass "times with units are accepted" || fail "units: rc=${rc}: ${out}"

# ---------------------------------------------------------------------------------------------------------------
echo "=== start the primary and the secondary ==="
"${KARIDNS}" -f "${TMP_DIR}/primary.conf" > "${PLOG}" 2>&1 &
PRI_PID=$!
i=0
while [ ${i} -lt 75 ]; do
    if [ -S "${SOCK}" ] && [ "$(www "${PORT}" rb.test)" = "192.0.2.10" ]; then break; fi
    sleep 0.2; i=$((i + 1))
done
[ "$(www "${PORT}" rb.test)" = "192.0.2.10" ] || { echo "FAIL: the primary did not start"; cat "${PLOG}"; exit 1; }
"${KARIDNS}" -f "${TMP_DIR}/secondary.conf" > "${SLOG}" 2>&1 &
SEC_PID=$!
wait_for 20 sec_is 1 192.0.2.10 && pass "the secondary has rb.test (serial 1)" || { fail "the secondary did not get rb.test"; tail -5 "${SLOG}"; }

# ---------------------------------------------------------------------------------------------------------------
echo "=== 2. nothing to go back to ==="
ctl main rollback rb.test;        expect "no reload yet: no previous version" 3 '^ERROR no previous version'
ctl main rollback;                expect "no zone name is a usage error" 2 'needs a zone name'
ctl main rollback nosuch.test;    expect "an unknown zone" 3 '^ERROR zone not found'
ctl main rollback sec.test;       expect "a secondary zone is refused" 3 '^ERROR rollback is for primary zones'
wz off.zone off.test 2 192.0.2.66
ctl main reload off.test;         expect "reload of the zone with rollback-window 0" 0 '^OK reloaded'
ctl main rollback off.test;       expect "rollback-window 0 keeps nothing" 3 '^ERROR rollback-window is 0'
"${KARICTL}" -h | grep -q 'rollback <zone> \[view\] \[local\]' && pass "the help lists rollback" || fail "help lacks rollback"

# ---------------------------------------------------------------------------------------------------------------
echo "=== 3. reload with bad data, rollback ==="
wz rb.zone rb.test 2 192.0.2.66 'bad IN A 192.0.2.67'
ctl main reload rb.test;          expect "reload brings the bad data" 0 '^OK reloaded'
[ "$(www "${PORT}" rb.test)" = "192.0.2.66" ] && pass "the primary serves the bad data" || fail "bad data not served"
ctl main zonestatus rb.test;      expect "zonestatus shows the previous version" 0 '^OK serial=2 .* previous version kept \(serial 1, [0-9]+ bytes, [0-9]+ s left\)'
ctl main status;                  expect "status shows the bytes kept for rollback" 0 'zone versions kept for rollback: database zones 0 bytes, other zones [1-9][0-9]* bytes'
wait_for 20 sec_is 2 192.0.2.66 && pass "the secondary follows the bad data (serial 2)" || fail "secondary did not reach serial 2"
ctl main rollback rb.test;        expect "rollback" 0 '^OK rolled back: serial 3 \(was 2\)$'
[ "$(www "${PORT}" rb.test)" = "192.0.2.10" ] && pass "the old data is served again" || fail "old data not served: $(www "${PORT}" rb.test)"
[ "$(serial "${PORT}" rb.test)" = "3" ] && pass "SOA serial = the bad serial + 1" || fail "serial: $(serial "${PORT}" rb.test)"
[ -z "$("${DAG}" @127.0.0.1 -p "${PORT}" bad.rb.test A +short +nohexdump +norec +timeout=2 2>/dev/null)" ] && pass "the record that came with the bad data is gone" || fail "bad.rb.test still answers"
ctl main zonestatus rb.test;      expect "zonestatus says rolled back" 0 '^OK serial=3 .* rolled back \(serial 3, from 2\)'
printf '%s\n' "${OUT}" | grep -q "previous version kept" && fail "prev should be consumed: ${OUT}" || pass "the previous version is consumed"
wait_for 20 sec_is 3 192.0.2.10 && pass "the secondary follows: serial 3 with the old data" || { fail "secondary did not follow the rollback: serial $(serial "${SPORT}" rb.test) www $(www "${SPORT}" rb.test)"; tail -5 "${SLOG}"; }
out=$("${DAG}" @127.0.0.1 -p "${PORT}" rb.test IXFR=2 +tcp +nohexdump 2>/dev/null)
printf '%s\n' "${out}" | grep -q '192\.0\.2\.66' && printf '%s\n' "${out}" | grep -q '192\.0\.2\.10' && pass "IXFR from the bad serial: deletes the bad data, adds the old" || fail "IXFR: ${out}"
grep -q 'Zone .rb.test.. rolled back: serial 3 (was 2)' "${PLOG}" && pass "the rollback is logged" || fail "no log line: $(grep -i rolled "${PLOG}")"

echo "=== 4. no redo ==="
ctl main rollback rb.test;        expect "a second rollback is refused" 3 '^ERROR no previous version'

# ---------------------------------------------------------------------------------------------------------------
echo "=== 5. the file did not change ==="
ctl main reload rb.test;          expect "reload <zone> keeps the rolled-back version" 0 '^OK kept the rolled-back version'
[ "$(www "${PORT}" rb.test)" = "192.0.2.10" ] && [ "$(serial "${PORT}" rb.test)" = "3" ] && pass "still the old data, serial 3" || fail "reload <zone> changed the zone"
ctl main reload;                  expect "a full reload" 0 '^OK reloaded'
[ "$(www "${PORT}" rb.test)" = "192.0.2.10" ] && [ "$(serial "${PORT}" rb.test)" = "3" ] && pass "the full reload keeps it too" || fail "full reload changed the zone: $(www "${PORT}" rb.test) $(serial "${PORT}" rb.test)"
ctl main zonestatus rb.test;      expect "still marked as rolled back" 0 'rolled back \(serial 3, from 2\)'
ctl main reload rb.test force;    expect "reload <zone> force reads the file again" 0 '^OK reloaded'
[ "$(www "${PORT}" rb.test)" = "192.0.2.66" ] && [ "$(serial "${PORT}" rb.test)" = "2" ] && pass "the bad file is served again (serial 2)" || fail "force: $(www "${PORT}" rb.test) $(serial "${PORT}" rb.test)"
ctl main zonestatus rb.test;      expect "the next publication ends the rolled-back state" 0 '^OK serial=2 '
printf '%s\n' "${OUT}" | grep -q "rolled back" && fail "still rolled back: ${OUT}"
# fix the file: the new version is served and rb.test has its prev again
wz rb.zone rb.test 5 192.0.2.10
ctl main reload rb.test;          expect "the fixed file" 0 '^OK reloaded'
[ "$(www "${PORT}" rb.test)" = "192.0.2.10" ] && [ "$(serial "${PORT}" rb.test)" = "5" ] && pass "fixed data, serial 5" || fail "fixed file not served"

# ---------------------------------------------------------------------------------------------------------------
echo "=== 6. a signed zone ==="
wz sig.zone sig.test 2 192.0.2.66 "${DNSKEY}"
ctl main reload sig.test;         expect "reload of the signed zone" 0 '^OK reloaded'
ctl main rollback sig.test;       expect "rollback of a signed zone is refused" 3 '^ERROR zone is signed; roll back in the DB and re-sign$'
[ "$(www "${PORT}" sig.test)" = "192.0.2.66" ] && [ "$(serial "${PORT}" sig.test)" = "2" ] && pass "nothing changed" || fail "the refused rollback changed the zone"
ctl main rollback sig.test local; expect "rollback local publishes the old version as it was" 0 '^OK rolled back \(local\): serial 1 \(was 2\); the secondaries do not follow$'
[ "$(www "${PORT}" sig.test)" = "192.0.2.10" ] && [ "$(serial "${PORT}" sig.test)" = "1" ] && pass "old data with its old serial" || fail "local rollback: $(www "${PORT}" sig.test) $(serial "${PORT}" sig.test)"
ctl main rollback sig.test local; expect "local rollback is also once" 3 '^ERROR no previous version'

# ---------------------------------------------------------------------------------------------------------------
echo "=== 7. the window ==="
wz exp.zone exp.test 2 192.0.2.66
ctl main reload exp.test;         expect "reload of the zone with rollback-window 2" 0 '^OK reloaded'
ctl main zonestatus exp.test;     expect "its previous version is kept" 0 'previous version kept \(serial 1,'
sleep 5
ctl main zonestatus exp.test;     expect "the window is over: the tick dropped it" 0 '^OK serial=2 '
printf '%s\n' "${OUT}" | grep -q "previous version kept" && fail "prev is still there: ${OUT}"
ctl main rollback exp.test;       expect "rollback after the window" 3 '^ERROR no previous version'

# ---------------------------------------------------------------------------------------------------------------
echo "=== 8. keys ==="
wz rb.zone rb.test 6 192.0.2.77
ctl main reload rb.test;          expect "another change" 0 '^OK reloaded'
ctl web rollback rb.test;         expect "a key without rollback is refused" 3 '^ERROR command not allowed for key "web"$'
[ "$(www "${PORT}" rb.test)" = "192.0.2.77" ] && pass "the refused rollback did nothing" || fail "refused rollback changed the zone"
ctl rbk rollback rb.test;         expect "a key with allow-commands { rollback; } may roll back" 0 '^OK rolled back: serial 7 \(was 6\)$'
[ "$(www "${PORT}" rb.test)" = "192.0.2.10" ] && pass "the old data is served" || fail "rbk rollback: $(www "${PORT}" rb.test)"
ctl rbk reload rb.test;           expect "that key may not reload" 3 '^ERROR command not allowed for key "rbk"$'
grep -q '\[Control\] key "rbk": rollback rb.test' "${PLOG}" && pass "an accepted rollback is logged with the key name" || fail "accepted rollback not logged"
grep -q '\[Control\] key "web": refused: rollback rb.test' "${PLOG}" && pass "a refused rollback is logged with the key name" || fail "refused rollback not logged"
kill -0 "${PRI_PID}" 2>/dev/null && pass "the server runs" || fail "the server is gone"

if [ "${FAILED}" -ne 0 ]; then
    echo "[FAIL] ${FAILED} check(s) failed"
    exit 1
fi
echo "[+] karictl rollback tests passed."
exit 0

#!/bin/sh
# ==============================================================================
# tests/run_ctl_restricted_key_test.sh - restricted control keys (control-channel { keys { } })
# ==============================================================================
# A control-channel with the unnamed full-power `secret`, a full-power key "admin" and a key "web" that is
# read-only with allow-commands { reload-zone; }.  Each key has its own karictl.conf (karictl is unchanged:
# it only needs the secret and the algorithm of the key it uses; "web" uses hmac-sha512, the others sha256).
#   1. karicheck conf: a valid file, the errors with file:line (unknown key, key listed twice, allow-commands
#      without read-only yes, unknown and test-only command), the warning for a key that is also a TSIG key
#   2. web: zonestatus / status / observatory and `reload <zone>` work; `reload`, `reconfig`, `stop`, `notify`,
#      `retransfer` are refused with ERROR command not allowed for key "web" (karictl exit 3), the server keeps
#      running, and the refusals are logged with the key name
#   3. admin and the unnamed secret run everything (reload, reconfig, notify); an unknown command is still the
#      old reply
#   4. a refusal keeps the connection open (one connection, several commands)
#   5. a wrong algorithm for a key and an unknown secret are AUTH_FAILED
#   6. reconfig with an unknown key in keys { } is refused and the running keys stay; a valid reconfig that gives
#      web `reload` takes effect for new connections; a server does not start with the bad file
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
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is needed for the raw control client"; exit 0; }
perl -MDigest::SHA -MMIME::Base64 -MIO::Socket::UNIX -e 1 2>/dev/null || { echo "SKIP: perl modules Digest::SHA, MIME::Base64, IO::Socket::UNIX are needed"; exit 0; }

TMP_DIR="$(mktemp -d /tmp/karidns_ctl_rkey.XXXXXX)"
chmod 755 "${TMP_DIR}"
CONF="${TMP_DIR}/karidns.conf"
SOCK="${TMP_DIR}/control.sock"
LOG="${TMP_DIR}/server.log"
SERVER_PID=""
FAILED=0

cleanup() {
    set +e
    [ -n "${SERVER_PID}" ] && kari_kill_tree "${SERVER_PID}"
    kari_kill_conf "${CONF}"
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

PORT=$(kari_port 0 $((27000 + $$ % 2000)))
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

b64() { printf '%s' "$1" | openssl base64 -A; }
MAIN_SECRET=$(b64 "ctl-test-main-secret-0123456789ab")
ADMIN_SECRET=$(b64 "ctl-test-admin-secret-0123456789a")
WEB_SECRET=$(b64 "ctl-test-web-secret-0123456789abc")
OTHER_SECRET=$(b64 "ctl-test-other-secret-0123456789")

cat > "${TMP_DIR}/ctl.zone" <<EOF
\$ORIGIN ctl.test.
\$TTL 300
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
EOF
chmod 644 "${TMP_DIR}/ctl.zone"

# write_conf FILE [web allow-commands] [extra keys entry] [extra statements]
write_conf() {
    cat > "$1" <<EOF
options { port ${PORT}; bind-address { 127.0.0.1; }; pid-file "none"; ${USER_OPT} };
key "admin" { algorithm hmac-sha256; secret "${ADMIN_SECRET}"; };
key "web" { algorithm hmac-sha512; secret "${WEB_SECRET}"; };
control-channel {
    socket "${SOCK}";
    secret "${MAIN_SECRET}";
    keys {
        "admin";
        "web" read-only yes allow-commands { ${2:-reload-zone;} };
        ${3:-}
    };
};
zone "ctl.test" { type master; file "${TMP_DIR}/ctl.zone"; };
${4:-}
EOF
    chmod 644 "$1"
}

# ctl_conf FILE SECRET ALGORITHM : a karictl.conf for one key
ctl_conf() {
    printf 'socket "%s";\nkey "karictl" { algorithm %s; secret "%s"; };\n' "${SOCK}" "$3" "$2" > "$1"
    chmod 600 "$1"
}
ctl_conf "${TMP_DIR}/main.conf" "${MAIN_SECRET}" hmac-sha256
ctl_conf "${TMP_DIR}/admin.conf" "${ADMIN_SECRET}" hmac-sha256
ctl_conf "${TMP_DIR}/web.conf" "${WEB_SECRET}" hmac-sha512
ctl_conf "${TMP_DIR}/web_wrongalg.conf" "${WEB_SECRET}" hmac-sha256
ctl_conf "${TMP_DIR}/other.conf" "${OTHER_SECRET}" hmac-sha256

# ctl CONFNAME args... : sets OUT and RC
ctl() {
    _c="${TMP_DIR}/$1.conf"
    shift
    OUT=$("${KARICTL}" -c "${_c}" -s "${SOCK}" "$@" 2>&1)
    RC=$?
}

# expect LABEL RC REGEX : after ctl
expect() {
    if [ "${RC}" -ne "$2" ]; then
        fail "$1: exit ${RC}, expected $2: ${OUT}"
    elif [ -n "$3" ] && ! printf '%s\n' "${OUT}" | grep -E -q "$3"; then
        fail "$1: output does not match '$3': ${OUT}"
    else
        pass "$1"
    fi
}

REFUSED_WEB='ERROR command not allowed for key "web"'

# ---------------------------------------------------------------------------------------------------------------
echo "=== 1. karicheck conf ==="
write_conf "${TMP_DIR}/ok.conf"
out=$("${KARICHECK}" conf "${TMP_DIR}/ok.conf" 2>&1); rc=$?
[ "${rc}" -eq 0 ] && pass "a valid file is accepted" || fail "valid file: rc=${rc}: ${out}"
printf '%s\n' "${out}" | grep -q "also used for TSIG" && fail "no TSIG warning expected: ${out}" || pass "no TSIG warning when the keys are only control keys"

write_conf "${TMP_DIR}/tsig.conf" "reload-zone;" "" 'zone "x.test" { type master; file "x"; allow-transfer { key admin; }; };'
out=$("${KARICHECK}" conf "${TMP_DIR}/tsig.conf" 2>&1); rc=$?
printf '%s\n' "${out}" | grep -E -q "tsig.conf:[0-9]+: control-channel: key 'admin' is also used for TSIG \(zone 'x.test.' allow-transfer\)" \
    && pass "a control key that is also in allow-transfer is a warning with file:line" || fail "TSIG warning missing: ${out}"
[ "${rc}" -eq 0 ] && pass "the TSIG warning is not an error (exit 0)" || fail "TSIG warning rc=${rc}"
printf '%s\n' "${out}" | grep -q "key 'web' is also used" && fail "web is not a TSIG key: ${out}" || pass "only the shared key is named"

check_error() { # label conf-extra-arg3 conf-arg2 regex
    write_conf "${TMP_DIR}/bad.conf" "$2" "$3"
    out=$("${KARICHECK}" conf "${TMP_DIR}/bad.conf" 2>&1); rc=$?
    if [ "${rc}" -ne 0 ] && printf '%s\n' "${out}" | grep -E -q "$4"; then pass "$1"; else fail "$1: rc=${rc}: ${out}"; fi
}
check_error "unknown key" "reload-zone;" '"nokey";' "bad.conf:[0-9]+: control-channel keys: unknown key 'nokey'"
check_error "key listed twice" "reload-zone;" '"web";' "bad.conf:[0-9]+: control-channel keys: key 'web' is listed twice"
check_error "unknown command" "restart;" "" "bad.conf:[0-9]+: control-channel keys: key 'web': allow-commands: 'restart' is not a command"
check_error "test-only command" "evict;" "" "'evict' is not a command that can be allowed"
check_error "allow-commands without read-only" "reload-zone;" '"admin" allow-commands { stop; };' \
    "bad.conf:[0-9]+: control-channel keys: key 'admin': allow-commands needs 'read-only yes'"
printf 'control-channel { socket "x"; frob 1; };\n' > "${TMP_DIR}/opt.conf"
out=$("${KARICHECK}" conf "${TMP_DIR}/opt.conf" 2>&1); rc=$?
[ "${rc}" -ne 0 ] && printf '%s\n' "${out}" | grep -q "(supported: socket, secret, algorithm, allow-group, keys)" && pass "the unknown-option message lists keys" || fail "unknown option: ${out}"

# ---------------------------------------------------------------------------------------------------------------
echo "=== start karidns ==="
write_conf "${CONF}"
"${KARIDNS}" -f "${CONF}" > "${LOG}" 2>&1 &
SERVER_PID=$!
READY=0
i=0
while [ ${i} -lt 75 ]; do
    if [ -S "${SOCK}" ] && "${DAG}" @127.0.0.1 -p "${PORT}" ctl.test SOA +short +timeout=1 +tries=1 2>/dev/null | grep -q hostmaster; then READY=1; break; fi
    sleep 0.2
    i=$((i + 1))
done
if [ "${READY}" -ne 1 ]; then
    echo "FAIL: karidns did not start"
    cat "${LOG}"
    exit 1
fi

alive() { kill -0 "${SERVER_PID}" 2>/dev/null; }

echo "=== 2. web: read-only plus reload-zone ==="
ctl web zonestatus ctl.test;  expect "web zonestatus" 0 '^OK serial=1 refresh=7200'
ctl web status;               expect "web status" 0 '^server is up and running$'
ctl web observatory;          expect "web observatory" 0 ''
ctl web dbstatus;             expect "web dbstatus (allowed: it reaches the command)" 3 'no database block'
ctl web reload ctl.test;      expect "web reload <zone> (reload-zone)" 0 '^OK reloaded'
for c in "reload" "reconfig" "stop" "notify ctl.test" "retransfer ctl.test" "rollback ctl.test"; do
    ctl web ${c};             expect "web ${c} is refused" 3 "^${REFUSED_WEB}\$"
done
alive && pass "the server runs after the refused stop" || fail "the server is gone"
ctl web zonestatus ctl.test;  expect "web still works after the refusals" 0 '^OK serial=1'
grep -q '\[Control\] key "web": refused: stop' "${LOG}" && pass "a refused command is logged with the key name" || fail "refusal not logged: $(grep Control "${LOG}" | tail -3)"
grep -q '\[Control\] key "web": reload ctl.test' "${LOG}" && pass "an accepted command is logged with the key name" || fail "accepted command not logged"
grep -q '\[Control\] key "web": zonestatus ctl.test' "${LOG}" && pass "a read-only command is logged too" || fail "zonestatus not logged"

echo "=== 3. admin and the unnamed secret ==="
ctl admin zonestatus ctl.test; expect "admin zonestatus" 0 '^OK serial=1'
ctl admin reload;             expect "admin reload (full)" 0 '^OK reloaded'
ctl admin reload ctl.test;    expect "admin reload <zone>" 0 '^OK reloaded'
ctl admin notify ctl.test;    expect "admin notify" 0 ''
ctl admin reconfig;           expect "admin reconfig" 0 '^OK'
ctl admin bogus_command;      expect "admin unknown command is the old reply" 3 '^ERROR unknown command$'
ctl admin rollback ctl.test;  expect "admin rollback reaches its command (nothing was reloaded with a change: no previous version)" 3 '^ERROR no previous version'
ctl main status;              expect "unnamed secret: status" 0 '^server is up and running$'
ctl main reload;              expect "unnamed secret: reload" 0 '^OK reloaded'
grep -q '\[Control\] key "admin": reload$' "${LOG}" && pass "admin is named in the log" || fail "admin not in the log"
grep -q '\[Control\] key "(main)": status$' "${LOG}" && pass "the unnamed secret is logged as (main)" || fail "(main) not in the log"

echo "=== 4. a refusal keeps the connection open ==="
out=$(perl tests/lib/ctrl_multi_client.pl "${SOCK}" "${WEB_SECRET}" sha512 reload reconfig stop "zonestatus ctl.test" "zonestatus ctl.test" 2>&1)
want='AUTH: OK
REPLY: '"${REFUSED_WEB}"'
REPLY: '"${REFUSED_WEB}"'
REPLY: '"${REFUSED_WEB}"
[ "$(printf '%s\n' "${out}" | head -4)" = "${want}" ] && pass "three refusals on one connection" || fail "refusals: ${out}"
printf '%s\n' "${out}" | sed -n 5p | grep -q '^REPLY: OK serial=1' && pass "then an allowed command on the same connection works" || fail "allowed command after refusals: ${out}"
printf '%s\n' "${out}" | sed -n 6p | grep -q '^REPLY: <closed>$' && pass "an accepted command ends the connection (as before)" || fail "connection after an accepted command: ${out}"
alive && pass "the server still runs" || fail "the server is gone"

echo "=== 5. wrong algorithm, unknown secret ==="
ctl web_wrongalg zonestatus ctl.test; expect "web's secret with sha256" 2 'Authentication failed'
ctl other zonestatus ctl.test;        expect "a secret that is no key's" 2 'Authentication failed'

echo "=== 6. reconfig ==="
# an unknown key: the reconfig is refused and the running keys stay
write_conf "${CONF}" "reload-zone;" '"nokey";'
ctl admin reconfig;           expect "reconfig with an unknown key is refused" 3 'configuration not applied'
ctl web reload;               expect "web is still refused after the refused reconfig" 3 "^${REFUSED_WEB}\$"
ctl web reload ctl.test;      expect "web reload <zone> still works" 0 '^OK reloaded'
grep -q "control-channel keys: unknown key 'nokey'" "${LOG}" && pass "the log names the unknown key" || fail "log lacks the unknown key"
# a server does not start with it
sed "s/port ${PORT};/port $((PORT + 1));/; s|${SOCK}|${TMP_DIR}/bad.sock|" "${CONF}" > "${TMP_DIR}/bad2.conf"
"${KARIDNS}" -f "${TMP_DIR}/bad2.conf" > "${TMP_DIR}/bad2.log" 2>&1 &
BAD_PID=$!
i=0
while [ ${i} -lt 50 ] && kill -0 "${BAD_PID}" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "${BAD_PID}" 2>/dev/null; then
    kari_kill_tree "${BAD_PID}"
    fail "karidns started with an unknown control key"
else
    wait "${BAD_PID}"; rc=$?
    [ "${rc}" -ne 0 ] && grep -q "unknown key 'nokey'" "${TMP_DIR}/bad2.log" && pass "startup with an unknown control key is refused" || fail "startup: rc=${rc} $(cat "${TMP_DIR}/bad2.log")"
fi
# a valid reconfig: web may also reload (full) now
write_conf "${CONF}" "reload-zone; reload;"
ctl admin reconfig;           expect "valid reconfig" 0 '^OK'
ctl web reload;               expect "web reload after allow-commands { reload; }" 0 '^OK reloaded'
ctl web reconfig;             expect "web reconfig is still refused" 3 "^${REFUSED_WEB}\$"
# dropping web from keys { }: its secret no longer works
write_conf "${CONF}" "reload-zone;"
sed 's/^        "web" read-only yes.*$//' "${CONF}" > "${TMP_DIR}/noweb.conf" && cp "${TMP_DIR}/noweb.conf" "${CONF}"
ctl admin reconfig;           expect "reconfig without web" 0 '^OK'
ctl web zonestatus ctl.test;  expect "web is gone" 2 'Authentication failed'
ctl admin zonestatus ctl.test; expect "admin still works" 0 '^OK serial=1'

echo "=== 7. allow-group (needs root and the users nobody and daemon; SKIP otherwise) ==="
if [ "$(id -u)" != "0" ]; then
    echo "  SKIP: not root (the socket is given to a group and the client runs as another user)"
elif ! id nobody >/dev/null 2>&1 || ! id daemon >/dev/null 2>&1 || [ "$(id -g nobody)" = "$(id -g daemon)" ]; then
    echo "  SKIP: the users nobody and daemon (with different primary groups) are needed"
else
    NG=$(id -gn nobody)
    kari_kill_tree "${SERVER_PID}"; SERVER_PID=""
    sleep 1
    # the server runs as daemon: the peer user "nobody" is let in only as a member of the allow-group
    write_conf "${CONF}" "reload-zone;"
    sed "s|user \"nobody\"; group \"nobody\";|user \"daemon\"; group \"daemon\";|; s|^    socket \"${SOCK}\";|    socket \"${SOCK}\"; allow-group \"${NG}\";|" "${CONF}" > "${TMP_DIR}/grp.conf"
    cp "${TMP_DIR}/grp.conf" "${CONF}"
    out=$("${KARICHECK}" conf "${CONF}" 2>&1); [ $? -eq 0 ] && pass "karicheck accepts allow-group ${NG}" || fail "karicheck allow-group: ${out}"
    "${KARIDNS}" -f "${CONF}" > "${LOG}" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ ${i} -lt 75 ] && ! { [ -S "${SOCK}" ] && "${DAG}" @127.0.0.1 -p "${PORT}" ctl.test SOA +short +timeout=1 +tries=1 2>/dev/null | grep -q hostmaster; }; do sleep 0.2; i=$((i + 1)); done
    kill -0 "${SERVER_PID}" 2>/dev/null || { fail "karidns with allow-group did not start"; tail -5 "${LOG}"; }
    mode=$(stat -f '%Lp %Sg' "${SOCK}" 2>/dev/null || stat -c '%a %G' "${SOCK}")
    [ "${mode}" = "660 ${NG}" ] && pass "the socket is 0660 and belongs to group ${NG}" || fail "socket mode/group: ${mode}"
    cp "${TMP_DIR}/web.conf" "${TMP_DIR}/web_nobody.conf"; chown nobody "${TMP_DIR}/web_nobody.conf"
    out=$(su -m nobody -c "'${KARICTL}' -c '${TMP_DIR}/web_nobody.conf' -s '${SOCK}' zonestatus ctl.test" 2>&1); rc=$?
    [ ${rc} -eq 0 ] && printf '%s\n' "${out}" | grep -q '^OK serial=1' && pass "a member of the group connects with its key" || fail "group member: rc=${rc} ${out}"
    out=$(su -m nobody -c "'${KARICTL}' -c '${TMP_DIR}/web_nobody.conf' -s '${SOCK}' reconfig" 2>&1); rc=$?
    [ ${rc} -eq 3 ] && printf '%s\n' "${out}" | grep -q "^${REFUSED_WEB}\$" && pass "the group member is still held to its key's commands" || fail "member reconfig: rc=${rc} ${out}"
    OUTSIDER=""
    for u in man uucp news www games; do
        if id "${u}" >/dev/null 2>&1 && [ "$(id -g "${u}")" != "$(id -g nobody)" ] && [ "$(id -u "${u}")" != "$(id -u daemon)" ]; then OUTSIDER="${u}"; break; fi
    done
    if [ -z "${OUTSIDER}" ]; then
        echo "  SKIP: no user outside the group (man, uucp, news, www, games) to try"
    else
        cp "${TMP_DIR}/web.conf" "${TMP_DIR}/web_out.conf"; chown "${OUTSIDER}" "${TMP_DIR}/web_out.conf"
        out=$(su -m "${OUTSIDER}" -c "'${KARICTL}' -c '${TMP_DIR}/web_out.conf' -s '${SOCK}' zonestatus ctl.test" 2>&1); rc=$?
        [ ${rc} -ne 0 ] && pass "a user outside the group (${OUTSIDER}) is refused even with the right key (rc ${rc})" || fail "outsider got in: ${out}"
    fi
    ctl admin zonestatus ctl.test; expect "root still connects" 0 '^OK serial=1'
    printf 'control-channel { socket "x"; allow-group "no_such_group_here"; };\n' > "${TMP_DIR}/g.conf"
    out=$("${KARICHECK}" conf "${TMP_DIR}/g.conf" 2>&1); rc=$?
    [ ${rc} -ne 0 ] && printf '%s\n' "${out}" | grep -q "g.conf:[0-9]*: control-channel: allow-group: group 'no_such_group_here' not found" && pass "an unknown group is an error with file:line" || fail "unknown group: rc=${rc} ${out}"
fi

if [ "${FAILED}" -ne 0 ]; then
    echo "[FAIL] ${FAILED} check(s) failed"
    exit 1
fi
echo "[+] Restricted control key tests passed."
exit 0

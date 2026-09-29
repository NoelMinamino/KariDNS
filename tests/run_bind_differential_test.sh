#!/bin/sh
# ==============================================================================
# tests/run_bind_differential_test.sh - BIND Differential Oracle Verification
#
# Serves tests/matrix/zones/wildcard.zone from KariDNS and from BIND (named)
# and compares the RCODE and the answer RRset of a few wildcard queries
# (RFC 4592). SKIP when named is not installed.
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
. "${SCRIPT_DIR}/lib_proc.sh"
cd "${ROOT_DIR}"

if ! command -v named >/dev/null 2>&1; then
    echo "SKIP: BIND (named) is not installed on this system"
    exit 0
fi

if [ ! -x "./karidns" ] || [ ! -x "./dag" ]; then
    echo "SKIP: karidns or dag binary not found"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karidns_bind_diff.XXXXXX 2>/dev/null || mktemp -d)"
chmod 0755 "${TMP_DIR}"
KARI_PORT=$((26000 + ( $$ % 10000 )))
BIND_PORT=$((36000 + ( $$ % 10000 )))
KARI_PID=""
BIND_PID=""

cleanup() {
    kari_kill_tree "${KARI_PID:-}" "${BIND_PID:-}"
    kari_kill_conf "${TMP_DIR}/karidns.conf"
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

# Start KariDNS (user/group: karidns refuses to run as root without them)
cat > "${TMP_DIR}/karidns.conf" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${TMP_DIR}/karidns.pid";
    listen-on { 127.0.0.1; };
    port ${KARI_PORT};
    user "nobody";
    group "nobody";
    minimal-responses yes;
};
zone "wildcard.test" {
    type master;
    file "${ROOT_DIR}/tests/matrix/zones/wildcard.zone";
};
EOF

./karidns -f "${TMP_DIR}/karidns.conf" > "${TMP_DIR}/karidns.log" 2>&1 &
KARI_PID=$!

# Start BIND named
cat > "${TMP_DIR}/named.conf" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "${TMP_DIR}/named.pid";
    listen-on port ${BIND_PORT} { 127.0.0.1; };
    listen-on-v6 { none; };
    minimal-responses yes;
    recursion no;
};
zone "wildcard.test" {
    type primary;
    file "${ROOT_DIR}/tests/matrix/zones/wildcard.zone";
};
EOF

named -c "${TMP_DIR}/named.conf" -g > "${TMP_DIR}/named.log" 2>&1 &
BIND_PID=$!

# Wait for both servers to be ready
KARI_UP=0
BIND_UP=0
for i in $(seq 1 50); do
    [ "$KARI_UP" = 1 ] || { ./dag @127.0.0.1 -p "${KARI_PORT}" wildcard.test SOA +short +timeout=1 +tries=1 2>/dev/null | grep -q . && KARI_UP=1; } || true
    [ "$BIND_UP" = 1 ] || { ./dag @127.0.0.1 -p "${BIND_PORT}" wildcard.test SOA +short +timeout=1 +tries=1 2>/dev/null | grep -q . && BIND_UP=1; } || true
    [ "$KARI_UP" = 1 ] && [ "$BIND_UP" = 1 ] && break
    sleep 0.2
done
if [ "$KARI_UP" != 1 ]; then
    echo "FAIL: KariDNS did not answer on port ${KARI_PORT}"
    cat "${TMP_DIR}/karidns.log"
    exit 1
fi
if [ "$BIND_UP" != 1 ]; then
    echo "FAIL: named did not answer on port ${BIND_PORT}"
    cat "${TMP_DIR}/named.log"
    exit 1
fi

echo "[+] Both KariDNS (port ${KARI_PORT}) and BIND (port ${BIND_PORT}) are online. Running differential queries..."

# "<status>|<sorted answer RDATA>" for one query
summarize() {
    _st=$(./dag @127.0.0.1 -p "$1" "$2" "$3" +timeout=2 +tries=1 2>/dev/null |
          sed -n 's/.*status: \([A-Z]*\),.*/\1/p')
    _an=$(./dag @127.0.0.1 -p "$1" "$2" "$3" +short +timeout=2 +tries=1 2>/dev/null | sort | tr '\n' ' ')
    echo "${_st}|${_an}"
}

DIFF_COUNT=0
for q in "foo.wildcard.test A" "foo.sub.wildcard.test AAAA" "exact.wildcard.test A" \
         "foo.wildcard.test TXT" "ent.sub.wildcard.test A" "nonexistent.exact.wildcard.test A"; do
    set -- $q
    KARI_OUT=$(summarize "${KARI_PORT}" "$1" "$2")
    BIND_OUT=$(summarize "${BIND_PORT}" "$1" "$2")
    case "${BIND_OUT}" in
        "|"*) echo "FAIL: no status line from named for $1 $2"; exit 1 ;;
    esac
    if [ "${KARI_OUT}" != "${BIND_OUT}" ]; then
        echo "[-] Differential mismatch for $1 $2: Kari=[${KARI_OUT}] vs BIND=[${BIND_OUT}]"
        DIFF_COUNT=$((DIFF_COUNT + 1))
    else
        echo "[+] $1 $2: ${KARI_OUT}"
    fi
done

if [ "${DIFF_COUNT}" -gt 0 ]; then
    echo "FAIL: ${DIFF_COUNT} differential mismatches detected with BIND"
    exit 1
fi

echo "[+] BIND differential tests matched 100%."
exit 0

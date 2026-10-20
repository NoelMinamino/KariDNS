#!/bin/sh
# run_dag_update_generic_rdata_test.sh - D16-2: dag accepts the RFC 3597 5 generic form ("\# <length> <hex>") in the
# RDATA of --update-add, --update-del-exact and the yxrrset prerequisite, for unknown and for known types.
# It used to fail with "Failed to serialize update-add record".  The wire is checked with +qr; nothing is sent.
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DAG="${1:-${DAG:-$BIN_DIR/dag}}"
[ -x "$DAG" ] || DAG="./dag"
if [ ! -x "$DAG" ]; then
    echo "SKIP: dag executable not found"
    exit 0
fi

FAILS=0
hexof() {   # the hex columns of the dumps in OUTPUT, as one string without blanks
    printf '%s\n' "$1" | awk '/^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]  / { printf "%s", substr($0, 7, 49) }' | tr -d ' '
}
check() {   # check DESCRIPTION OUTPUT PATTERN: PATTERN is in the text, or (blanks removed) in the hex dump
    if printf '%s\n' "$2" | grep -qi -- "$3" || hexof "$2" | grep -qi -- "$(printf '%s' "$3" | tr -d ' ')"; then echo "  [ OK ] $1"
    else FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; printf '%s\n' "$2" | head -20; fi
}
absent() {
    if printf '%s\n' "$2" | grep -qi -- "$3"; then FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; printf '%s\n' "$2" | head -10
    else echo "  [ OK ] $1"; fi
}
run() { "$DAG" @127.0.0.1 -p 9 example.test SOA +qr +timeout=1 +tries=1 "$@" 2>&1 || true; }

OUT=$(run --update-add 'x.example.test 300 IN TYPE65534 \# 0')
absent "update-add TYPE65534 \\# 0: no serialization failure" "$OUT" "Failed to serialize"
check "update-add TYPE65534 \\# 0: TYPE fffe, CLASS IN, TTL 300, RDLENGTH 0" "$OUT" "ff fe 00 01 00 00 01 2c 00 00"

OUT=$(run --update-add 'x.example.test 300 IN TYPE65534 \# 3 0a0b0c')
check "update-add unknown type with RDATA: RDLENGTH 3 and the octets" "$OUT" "00 03 0a 0b 0c"

OUT=$(run --update-add 'x.example.test 300 IN TXT \# 4 03610062')
absent "update-add TXT \\# 4 (a NUL octet): no serialization failure" "$OUT" "Failed to serialize"
check "update-add TXT with a NUL octet: RDLENGTH 4, 03 61 00 62" "$OUT" "00 04 03 61 00 62"

OUT=$(run --update-add 'x.example.test 300 IN A \# 4 c0000201')
check "update-add A in the generic form: 192.0.2.1" "$OUT" "00 04 c0 00 02 01"

OUT=$(run --update-add 'x.example.test 300 IN TYPE65534 \# 2 0a' )
check "a length that does not match the data is refused" "$OUT" "does not match the declared length"
OUT=$(run --update-add 'x.example.test 300 IN PTR \# 0')
check "RDATA that is not valid for a known type is refused" "$OUT" "Failed to serialize update-add record"
OUT=$(run --update-add 'x.example.test 300 IN A \# 3 c00002')
check "a fixed-size type with the wrong length is refused" "$OUT" "fixed-size"

OUT=$(run --update-del-exact 'x.example.test IN TYPE65534 \# 3 0a0b0c')
absent "update-del-exact generic form: no serialization failure" "$OUT" "Failed to serialize"
check "update-del-exact generic form: CLASS NONE, RDLENGTH 3" "$OUT" "ff fe 00 fe 00 00 00 00 00 03 0a 0b 0c"

OUT=$(run --prereq-yxrrset 'x.example.test TYPE65534 \# 2 0a0b')
absent "yxrrset prerequisite generic form: no serialization failure" "$OUT" "Failed to serialize"
check "yxrrset prerequisite generic form: CLASS ANY... RDLENGTH 2" "$OUT" "00 02 0a 0b"

OUT=$(run --update-add 'x.example.test 300 IN TXT "plain text"')
check "a record in the presentation format still works" "$OUT" "70 6c 61 69 6e"

if [ "$FAILS" -eq 0 ]; then echo "PASS: run_dag_update_generic_rdata_test"; exit 0; fi
echo "FAIL: $FAILS check(s)"
exit 1

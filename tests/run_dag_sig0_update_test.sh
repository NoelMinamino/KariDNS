#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) RFC 3007 / RFC 2931 SIG(0) Client-Side Transaction Signing Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building tools/dag with make ==="
make -C "$ROOT_DIR" dag

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"
if [ ! -x "$DAG" ]; then
    echo "Error: dag executable not found at $DAG"
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl command required for test key generation"
    exit 1
fi

TEST_TMPDIR=$(mktemp -d /tmp/dag_sig0_test_XXXXXX 2>/dev/null || mktemp -d -t 'dag_sig0_test')
cleanup() {
    rm -rf "$TEST_TMPDIR"
}
trap cleanup EXIT INT TERM

cd "$TEST_TMPDIR"

echo "=== Generating test private keys (ECDSA P-256, Ed25519, RSA 2048) ==="
# 1. ECDSA P-256 (Alg 13)
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa.key 2>/dev/null
# 2. Ed25519 (Alg 15)
openssl genpkey -algorithm ed25519 -out ed25519.key 2>/dev/null
# 3. RSA 2048 (Alg 8)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key 2>/dev/null

FAILED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    printf "Test: %s ... " "$NAME"
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$EXPECT"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

run_not_check() {
    NAME="$1"
    CMD="$2"
    UNEXPECT="$3"
    printf "Test: %s (should NOT match '%s') ... " "$NAME" "$UNEXPECT"
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$UNEXPECT"; then
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Unexpected match: $UNEXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    else
        echo "OK"
    fi
}

echo ""
echo "=== 1. Testing CLI Option Validation & Mutual Exclusion ==="

# +sig0-pkey requires +sig0-name
run_check "+sig0-pkey without +sig0-name fails" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +timeout=1" \
    "(error: SIG\(0\) requires a signer name)"

# TSIG and SIG(0) are mutually exclusive (+sig0-pkey then -y)
run_check "+sig0-pkey with -y fails" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=key.example. -y hmac-sha256:tsigkey:c2VjcmV0 +timeout=1" \
    "(error: TSIG \(-k/-y\) and SIG\(0\) \(\+sig0-pkey\) cannot be combined)"

# TSIG and SIG(0) are mutually exclusive (-y then +sig0-pkey)
run_check "-y with +sig0-pkey fails" \
    "$DAG example.com @127.0.0.1 -y hmac-sha256:tsigkey:c2VjcmV0 +sig0-pkey=ecdsa.key +sig0-name=key.example. +timeout=1" \
    "(error: TSIG \(-k/-y\) and SIG\(0\) \(\+sig0-pkey\) cannot be combined)"

# Non-existent key file fails
run_check "+sig0-pkey non-existent file fails" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=nonexistent.pem +sig0-name=key.example. +timeout=1" \
    "(error: could not open SIG\(0\) private key file)"

# +sig0-alg invalid range (>255)
run_check "+sig0-alg invalid value fails" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=key.example. +sig0-alg=999 +timeout=1" \
    "(error: invalid algorithm number '999' for \+sig0-alg)"

# +sig0-keytag invalid range (>65535)
run_check "+sig0-keytag invalid value fails" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=key.example. +sig0-keytag=70000 +timeout=1" \
    "(error: invalid key tag '70000' for \+sig0-keytag)"

# +nosig0 disables signing even when +sig0-pkey is given
run_not_check "+nosig0 suppresses SIG(0) signing" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=key.example. +nosig0 +qr +timeout=1" \
    "(IN[[:space:]]+SIG[[:space:]]|ANY[[:space:]]+SIG[[:space:]])"

echo ""
echo "=== 2. Testing ECDSA P-256 (Alg 13) SIG(0) Transaction Signing ==="

# In +qr output, check SIG record structure:
# Owner: .  CLASS: ANY  TYPE: SIG  Type Covered: 0  Alg: 13  Labels: 0  OrigTTL: 0
run_check "ECDSA P-256 auto-detected Alg 13 and Type Covered 0" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +fuzztime=1700000000 +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+13[[:space:]]+0[[:space:]]+0"

# Verify deterministic timestamp from +fuzztime (1700000000 -> Expiration 20231114221820, Inception 20231114221320)
run_check "Deterministic inception/expiration timestamps via +fuzztime" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +fuzztime=1700000000 +qr +timeout=1" \
    "20231114221820[[:space:]]+20231114221320"

# Verify Signer Name in SIG record
run_check "Signer name present in SIG record" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +fuzztime=1700000000 +qr +timeout=1" \
    "update-key\.example\.com\."

# Ensure Type Covered is rendered as "0" and NOT "TYPE0"
run_not_check "Type Covered is '0' and NOT 'TYPE0'" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +qr +timeout=1" \
    "SIG[[:space:]]+TYPE0"

echo ""
echo "=== 3. Testing Ed25519 (Alg 15) SIG(0) Transaction Signing ==="

# Ed25519 auto-detect Alg 15
run_check "Ed25519 auto-detected Alg 15 and Type Covered 0" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ed25519.key +sig0-name=ed-key.example.com. +fuzztime=1700000000 +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+15[[:space:]]+0[[:space:]]+0"

echo ""
echo "=== 4. Testing RSA (Alg 8) SIG(0) Transaction Signing ==="

# RSA auto-detect Alg 8
run_check "RSA 2048 auto-detected Alg 8 and Type Covered 0" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=rsa.key +sig0-name=rsa-key.example.com. +fuzztime=1700000000 +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+8[[:space:]]+0[[:space:]]+0"

echo ""
echo "=== 5. Testing Key Tag Override & Algorithm Override ==="

# Explicit +sig0-keytag=54321
run_check "+sig0-keytag override appears in SIG RR" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +sig0-keytag=54321 +fuzztime=1700000000 +qr +timeout=1" \
    "54321[[:space:]]+update-key\.example\.com\."

# Explicit +sig0-alg=13 override on ECDSA key
run_check "+sig0-alg override parameter accepted" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +sig0-alg=13 +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+13"

echo ""
echo "=== 6. Testing Dynamic DNS UPDATE (RFC 2136 + RFC 3007) ==="

# Formulate Dynamic UPDATE request with --update-add and verify sections:
# opcode: UPDATE, Zone section (SOA), Update section (A), Additional section (SIG)
run_check "Dynamic UPDATE has opcode: UPDATE" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. --update-add 'new.example.com 300 IN A 192.0.2.1' +qr +timeout=1" \
    "opcode: UPDATE"

run_check "Dynamic UPDATE has Zone section" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. --update-add 'new.example.com 300 IN A 192.0.2.1' +qr +timeout=1" \
    ";; ZONE SECTION:"

run_check "Dynamic UPDATE has Update record in UPDATE SECTION" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. --update-add 'new.example.com 300 IN A 192.0.2.1' +qr +timeout=1" \
    "new\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.1"

run_check "Dynamic UPDATE has SIG(0) in ADDITIONAL SECTION" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. --update-add 'new.example.com 300 IN A 192.0.2.1' +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+13"

echo ""
echo "=== 7. Verifying Signature Byte-Length Encoding ==="

# For ECDSA P-256 (Alg 13), signature MUST be raw r || s (64 bytes).
SIG_B64=$($DAG example.com @127.0.0.1 +sig0-pkey=ecdsa.key +sig0-name=update-key.example.com. +fuzztime=1700000000 +nosplit +qr +timeout=1 2>&1 | \
    grep "ANY[[:space:]]*SIG" | awk '{print $NF}')

SIG_RAW_LEN=$(echo "$SIG_B64" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')
printf "Test: ECDSA P-256 signature raw length is exactly 64 bytes ... "
if [ "$SIG_RAW_LEN" = "64" ]; then
    echo "OK ($SIG_RAW_LEN bytes)"
else
    echo "FAILED (got $SIG_RAW_LEN bytes, expected 64)"
    FAILED=$((FAILED + 1))
fi

# For Ed25519 (Alg 15), signature MUST be raw 64 bytes.
SIG_ED_B64=$($DAG example.com @127.0.0.1 +sig0-pkey=ed25519.key +sig0-name=ed-key.example.com. +fuzztime=1700000000 +nosplit +qr +timeout=1 2>&1 | \
    grep "ANY[[:space:]]*SIG" | awk '{print $NF}')

SIG_ED_RAW_LEN=$(echo "$SIG_ED_B64" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')
printf "Test: Ed25519 signature raw length is exactly 64 bytes ... "
if [ "$SIG_ED_RAW_LEN" = "64" ]; then
    echo "OK ($SIG_ED_RAW_LEN bytes)"
else
    echo "FAILED (got $SIG_ED_RAW_LEN bytes, expected 64)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== 8. Testing BIND .private Keyfile Format Auto-Detection via -k and +sig0-pkey ==="

# Synthesize a valid BIND .private keyfile (Ed25519)
cat << 'EOF' > Kbind-ed.example.com.+015+12345.private
Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
EOF

cat << 'EOF' > Kbind-ed.example.com.+015+12345.key
; This is a zone-signing key, keyid 12345, for bind-ed.example.com.
bind-ed.example.com. IN KEY 512 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
EOF

# Test 1: -k with .private auto-detects SIG(0) and signs outgoing query without needing +sig0-name
run_check "-k auto-detects BIND .private format and signs with SIG(0)" \
    "$DAG example.com @127.0.0.1 -k Kbind-ed.example.com.+015+12345.private +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+15[[:space:]]+0[[:space:]]+0[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+12345[[:space:]]+bind-ed\.example\.com\."

# Test 2: -k with .private format is mutually exclusive with -y
run_check "-k .private with -y fails mutual exclusion" \
    "$DAG example.com @127.0.0.1 -k Kbind-ed.example.com.+015+12345.private -y hmac-sha256:tsig:secret +timeout=1" \
    "(error: TSIG \(-k/-y\) and SIG\(0\) \(\+sig0-pkey\) cannot be combined)"

# Test 3: +sig0-pkey accepts BIND .private format
run_check "+sig0-pkey accepts BIND .private format" \
    "$DAG example.com @127.0.0.1 +sig0-pkey=Kbind-ed.example.com.+015+12345.private +qr +timeout=1" \
    "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+15"

# Test 4: Real dnssec-keygen generated keys if dnssec-keygen is installed
if command -v dnssec-keygen >/dev/null 2>&1; then
    echo "--- Testing with system dnssec-keygen ---"
    K_SYS_ECDSA=$(dnssec-keygen -a ECDSAP256SHA256 -b 256 -n USER -K . sys-ecdsa.example.com. 2>/dev/null || true)
    if [ -n "$K_SYS_ECDSA" ] && [ -f "$K_SYS_ECDSA.private" ]; then
        run_check "System dnssec-keygen ECDSA P-256 via -k" \
            "$DAG example.com @127.0.0.1 -k $K_SYS_ECDSA.private +qr +timeout=1" \
            "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+13"
    fi
    K_SYS_ED=$(dnssec-keygen -a ED25519 -n USER -K . sys-ed.example.com. 2>/dev/null || true)
    if [ -n "$K_SYS_ED" ] && [ -f "$K_SYS_ED.private" ]; then
        run_check "System dnssec-keygen Ed25519 via -k" \
            "$DAG example.com @127.0.0.1 -k $K_SYS_ED.private +qr +timeout=1" \
            "\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+SIG[[:space:]]+0[[:space:]]+15"
    fi
fi

echo ""
echo "========================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "ALL SIG(0) TESTS PASSED SUCCESSFULLY!"
    exit 0
else
    echo "TOTAL FAILURES: $FAILED"
    exit 1
fi

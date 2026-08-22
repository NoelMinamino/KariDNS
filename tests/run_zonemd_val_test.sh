#!/bin/sh
set -e

KARICHECK="./karicheck"
if [ ! -x "$KARICHECK" ]; then
    if [ -x "./tools/karicheck" ]; then
        KARICHECK="./tools/karicheck"
    else
        echo "karicheck binary not found. Run make first."
        exit 1
    fi
fi

echo "[+] Testing invalid ZONEMD scheme and halg range checks in karicheck..."

OUT=$("$KARICHECK" zone example. tests/zones/zonemd_invalid_val.zone 2>&1 || true)
echo "$OUT"

SCHEME_WARN_COUNT=$(echo "$OUT" | grep -c "ZONEMD scheme '257' is not a valid number (0-255)" || true)
if [ "$SCHEME_WARN_COUNT" -eq 1 ]; then
    echo "[+] Scheme range check warning confirmed (exactly 1 time)."
else
    echo "[-] FAIL: Expected scheme warning exactly 1 time, got $SCHEME_WARN_COUNT."
    exit 1
fi

HALG_WARN_COUNT=$(echo "$OUT" | grep -c "ZONEMD hash algorithm '257' is not a valid number (0-255)" || true)
if [ "$HALG_WARN_COUNT" -eq 1 ]; then
    echo "[+] Hash algorithm range check warning confirmed (exactly 1 time)."
else
    echo "[-] FAIL: Expected hash algorithm warning exactly 1 time, got $HALG_WARN_COUNT."
    exit 1
fi

echo "[+] Testing incomplete ZONEMD (fewer than 4 fields) in karicheck..."
OUT_SHORT=$("$KARICHECK" zone example. tests/zones/zonemd_short_rdata.zone 2>&1 || true)
echo "$OUT_SHORT"

if echo "$OUT_SHORT" | grep -q "fewer than 4 fields"; then
    echo "[+] Fewer than 4 fields warning confirmed."
else
    echo "[-] FAIL: Expected 'fewer than 4 fields' warning not found in output."
    exit 1
fi

echo "[+] Testing DNSSEC-signed ZONEMD zone verification (RFC 8976 Appendix A.4 uri.arpa.)..."
OUT_A4=$("$KARICHECK" zone uri.arpa. tests/zones/zonemd_a4.zone 2>&1)
echo "$OUT_A4"

if echo "$OUT_A4" | grep -q "is VALID"; then
    echo "[+] DNSSEC-signed ZONEMD digest verified successfully."
else
    echo "[-] FAIL: ZONEMD digest verification failed for signed zone uri.arpa."
    exit 1
fi

echo "[+] All ZONEMD validation tests passed successfully."
exit 0

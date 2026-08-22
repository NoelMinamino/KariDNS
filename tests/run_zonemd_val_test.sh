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

if echo "$OUT" | grep -q "ZONEMD scheme '257' is not a valid number (0-255)"; then
    echo "[+] Scheme range check warning confirmed."
else
    echo "[-] FAIL: Expected scheme warning not found in output."
    exit 1
fi

if echo "$OUT" | grep -q "ZONEMD hash algorithm '257' is not a valid number (0-255)"; then
    echo "[+] Hash algorithm range check warning confirmed."
else
    echo "[-] FAIL: Expected hash algorithm warning not found in output."
    exit 1
fi

echo "[+] All ZONEMD range check tests passed successfully."
exit 0

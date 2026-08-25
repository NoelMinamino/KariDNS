#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARICHECK="$ROOT/karicheck"

echo "[*] Building karicheck..."
make -C "$ROOT" karicheck

CONF_VALID_LOG="$DIR/conf_valid_log.conf"
CONF_UNDEF_QLOG="$DIR/conf_undef_qlog.conf"
CONF_UNDEF_RLOG="$DIR/conf_undef_rlog.conf"
CONF_MULTI_KEY="$DIR/conf_multi_key_acl.conf"

cleanup() {
    rm -f "$CONF_VALID_LOG" "$CONF_UNDEF_QLOG" "$CONF_UNDEF_RLOG" "$CONF_MULTI_KEY"
}
trap cleanup EXIT INT TERM

cat << 'EOF' > "$CONF_VALID_LOG"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
logging {
    channel query_log { file "/tmp/queries.log"; };
    channel resp_log { file "/tmp/responses.log"; };
    category queries { query_log; };
    category responses { resp_log; };
};
EOF

cat << 'EOF' > "$CONF_UNDEF_QLOG"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
logging {
    channel query_log { file "/tmp/queries.log"; };
    category queries { non_existent_query_channel; };
};
EOF

cat << 'EOF' > "$CONF_UNDEF_RLOG"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
logging {
    channel resp_log { file "/tmp/responses.log"; };
    category responses { non_existent_resp_channel; };
};
EOF

cat << 'EOF' > "$CONF_MULTI_KEY"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
zone "example.com" {
    type master;
    file "zones/example.zone";
    allow-transfer { key "key1"; key "key2"; };
};
EOF

echo "[*] Testing karicheck on valid logging configuration..."
if ! "$KARICHECK" conf "$CONF_VALID_LOG" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have accepted valid logging configuration!"
    exit 1
fi
echo "[OK] karicheck accepted valid logging configuration."

echo "[*] Testing karicheck on undefined query logging channel..."
if "$KARICHECK" conf "$CONF_UNDEF_QLOG" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected undefined query logging channel!"
    exit 1
fi
echo "[OK] karicheck correctly rejected undefined query logging channel."

echo "[*] Testing karicheck on undefined response logging channel..."
if "$KARICHECK" conf "$CONF_UNDEF_RLOG" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have rejected undefined response logging channel!"
    exit 1
fi
echo "[OK] karicheck correctly rejected undefined response logging channel."

echo "[*] Testing karicheck on allow-transfer with multiple keys..."
if ! "$KARICHECK" conf "$CONF_MULTI_KEY" > /dev/null 2>&1; then
    echo "[FAIL] karicheck should have parsed allow-transfer with multiple keys!"
    exit 1
fi
echo "[OK] karicheck processed allow-transfer with multiple keys."

echo "[PASS] All logging channel validation and multi-key ACL checks passed successfully!"
exit 0

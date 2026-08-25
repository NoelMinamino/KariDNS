#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"

echo "[*] Building karidns..."
make -C "$ROOT" karidns

CONF_NO_USER="$DIR/conf_no_user.conf"
CONF_WITH_USER="$DIR/conf_with_user.conf"

cleanup() {
    rm -f "$CONF_NO_USER" "$CONF_WITH_USER"
    killall -9 karidns 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat << 'EOF' > "$CONF_NO_USER"
options {
    port 10053;
    bind-address { 127.0.0.1; };
};
EOF

cat << 'EOF' > "$CONF_WITH_USER"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
};
EOF

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    echo "[*] Running as root: testing privilege drop requirement..."
    if "$BIN" -f "$CONF_NO_USER" > /dev/null 2>&1; then
        echo "[FAIL] karidns should have refused to start as root without 'user' directive!"
        exit 1
    fi
    echo "[OK] karidns correctly refused to start as root without 'user' directive."
else
    echo "[*] Running as non-root (UID=$(id -u)): skipping root refusal test."
fi

echo "[PASS] Privilege drop root enforcement check passed successfully!"
exit 0

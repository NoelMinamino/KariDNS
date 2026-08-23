#!/bin/bash
set -e

# build_dmg.sh - Build macOS Universal Binary & DMG for dag
# Usage: ./packaging/macos/build_dmg.sh [version] [output_dir]

VERSION="${1:-1.0.0}"
VERSION="${VERSION#v}" # Strip leading 'v'
OUT_DIR="${2:-./dist}"

echo "==> Building dag Universal Binary for macOS (arm64 + x86_64, version ${VERSION})..."

mkdir -p "${OUT_DIR}"
BUILD_TMP="$(mktemp -d -t dag-macos-XXXXXX)"

OPENSSL_ARM64="/opt/homebrew/opt/openssl@3"
OPENSSL_X86_64="/usr/local/opt/openssl@3"

# Determine available OpenSSL paths
if [ -d "$OPENSSL_ARM64" ]; then
    SSL_ARM_INC="-I${OPENSSL_ARM64}/include"
    SSL_ARM_LIB="-L${OPENSSL_ARM64}/lib"
elif [ -d "$OPENSSL_X86_64" ]; then
    SSL_ARM_INC="-I${OPENSSL_X86_64}/include"
    SSL_ARM_LIB="-L${OPENSSL_X86_64}/lib"
else
    SSL_ARM_INC=""
    SSL_ARM_LIB=""
fi

# 1. Build arm64
echo "==> Compiling arm64 slice..."
clang -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -target arm64-apple-macos11.0 \
      ${SSL_ARM_INC} tools/dag.c dns_wire.c dns_utils.c dns_zone_parser.c \
      -o "${BUILD_TMP}/dag-arm64" ${SSL_ARM_LIB} -pthread -lcrypto -lssl -lz -lm

# 2. Build x86_64
echo "==> Compiling x86_64 slice..."
clang -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -target x86_64-apple-macos10.15 \
      ${SSL_ARM_INC} tools/dag.c dns_wire.c dns_utils.c dns_zone_parser.c \
      -o "${BUILD_TMP}/dag-x86_64" ${SSL_ARM_LIB} -pthread -lcrypto -lssl -lz -lm

# 3. Create Universal Binary
echo "==> Creating Universal binary with lipo..."
lipo -create -output "${BUILD_TMP}/dag" "${BUILD_TMP}/dag-arm64" "${BUILD_TMP}/dag-x86_64"

# 4. Create Tarball
echo "==> Creating macOS Universal tar.gz..."
STAGE_DIR="$(mktemp -d -t dag-dmg-stage-XXXXXX)"
mkdir -p "${STAGE_DIR}/dag-${VERSION}"
cp "${BUILD_TMP}/dag" "${STAGE_DIR}/dag-${VERSION}/"
cp LICENSE "${STAGE_DIR}/dag-${VERSION}/" 2>/dev/null || true
cp README.md "${STAGE_DIR}/dag-${VERSION}/" 2>/dev/null || true
cp docs/dag.md "${STAGE_DIR}/dag-${VERSION}/" 2>/dev/null || true

tar -czf "${OUT_DIR}/dag-${VERSION}-macos-universal.tar.gz" -C "${STAGE_DIR}" "dag-${VERSION}"

# 5. Create DMG
echo "==> Creating macOS DMG..."
DMG_STAGE="$(mktemp -d -t dag-dmg-root-XXXXXX)"
mkdir -p "${DMG_STAGE}/bin"
cp "${BUILD_TMP}/dag" "${DMG_STAGE}/bin/dag"
cp LICENSE "${DMG_STAGE}/" 2>/dev/null || true
cp README.md "${DMG_STAGE}/" 2>/dev/null || true
cp docs/dag.md "${DMG_STAGE}/" 2>/dev/null || true

# Simple install guide text
cat << 'EOF' > "${DMG_STAGE}/INSTALL.txt"
DAG (DNS Anomaly Generator) - Installation Guide

To install the `dag` command into your system:
  1. Open Terminal
  2. Copy the binary to /usr/local/bin:
     sudo cp /Volumes/DAG/bin/dag /usr/local/bin/
  3. Ensure it is executable:
     sudo chmod +x /usr/local/bin/dag

To verify:
  dag www.google.com A @8.8.8.8
EOF

hdiutil create -volname "DAG" -srcfolder "${DMG_STAGE}" -ov -format UDZO "${OUT_DIR}/dag-${VERSION}-macos.dmg"

# Cleanup
rm -rf "${BUILD_TMP}" "${STAGE_DIR}" "${DMG_STAGE}"

echo "==> macOS packages generated in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"/dag*

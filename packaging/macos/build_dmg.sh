#!/bin/bash
set -e

# build_dmg.sh - Build macOS DMG and tar.gz for dag
# Usage: ./packaging/macos/build_dmg.sh [version] [output_dir]

VERSION="${1:-1.0.0}"
VERSION="${VERSION#v}" # Strip leading 'v'
OUT_DIR="${2:-./dist}"
ARCH="$(uname -m)"

echo "==> Building dag binary for macOS (${ARCH}, version ${VERSION})..."

mkdir -p "${OUT_DIR}"
STAGE_DIR="$(mktemp -d -t dag-dmg-stage-XXXXXX)"

# Determine OpenSSL & libidn2 paths from Homebrew
OPENSSL_DIR="$(brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)"
IDN2_DIR="$(brew --prefix libidn2 2>/dev/null || echo /usr/local/opt/libidn2)"

SSL_INC=""
SSL_LIB=""
if [ -d "$OPENSSL_DIR" ]; then
    SSL_INC="-I${OPENSSL_DIR}/include"
    SSL_LIB="-L${OPENSSL_DIR}/lib"
fi

IDN_INC=""
IDN_LIB=""
IDN_DEF=""
if [ -d "$IDN2_DIR" ]; then
    IDN_INC="-I${IDN2_DIR}/include"
    IDN_LIB="-L${IDN2_DIR}/lib -lidn2"
    IDN_DEF="-DHAVE_LIBIDN2"
fi

# Build native binary for the current runner architecture
echo "==> Compiling dag for ${ARCH}..."
clang -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -pie -DKARIDNS_VERSION=\"${VERSION}\" \
      ${SSL_INC} ${IDN_INC} ${IDN_DEF} \
      tools/dag.c dns_wire.c dns_utils.c dns_zone_parser.c \
      -o "${STAGE_DIR}/dag" \
      ${SSL_LIB} ${IDN_LIB} -pthread -lcrypto -lssl -lz -lm

# 1. Create Standalone Binary Tarball
echo "==> Packaging tar.gz release for macOS ${ARCH}..."
TAR_STAGE="$(mktemp -d -t dag-tar-XXXXXX)"
mkdir -p "${TAR_STAGE}/dag-${VERSION}"
cp "${STAGE_DIR}/dag" "${TAR_STAGE}/dag-${VERSION}/"
cp LICENSE "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true
cp README.md "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true
cp docs/dag.md "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true

tar -czf "${OUT_DIR}/dag-${VERSION}-macos-${ARCH}.tar.gz" -C "${TAR_STAGE}" "dag-${VERSION}"
rm -rf "${TAR_STAGE}"

# 2. Create DMG
echo "==> Packaging DMG for macOS ${ARCH}..."
DMG_STAGE="$(mktemp -d -t dag-dmg-root-XXXXXX)"
mkdir -p "${DMG_STAGE}/bin"
cp "${STAGE_DIR}/dag" "${DMG_STAGE}/bin/dag"
cp LICENSE "${DMG_STAGE}/" 2>/dev/null || true
cp README.md "${DMG_STAGE}/" 2>/dev/null || true
cp docs/dag.md "${DMG_STAGE}/" 2>/dev/null || true

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

hdiutil create -volname "DAG" -srcfolder "${DMG_STAGE}" -ov -format UDZO "${OUT_DIR}/dag-${VERSION}-macos-${ARCH}.dmg"

# Cleanup
rm -rf "${STAGE_DIR}" "${DMG_STAGE}"

echo "==> macOS packages generated in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"/dag*

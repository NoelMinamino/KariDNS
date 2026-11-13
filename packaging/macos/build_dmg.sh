#!/bin/bash
set -e

# build_dmg.sh - Build macOS DMG and tar.gz for dag
# Usage: ./packaging/macos/build_dmg.sh [version] [output_dir]

VERSION_ARG="${1:-}"; . packaging/version.sh   # the file VERSION when no number is given
OUT_DIR="${2:-./dist}"
ARCH="$(uname -m)"

echo "==> Building dag binary for macOS (${ARCH}, version ${VERSION})..."

mkdir -p "${OUT_DIR}"
STAGE_DIR="$(mktemp -d -t dag-dmg-stage-XXXXXX)"

if [ ! -f dag ]; then
    echo "==> Building dag binary for macOS (${ARCH}, version ${VERSION})..."
    ./configure --march=none --with-db-drivers=none
    make clean || true
    make VERSION="${VERSION}" dag
else
    echo "==> Using existing dag binary for macOS (${ARCH}, version ${VERSION})..."
fi

cp dag "${STAGE_DIR}/dag"


# 1. Create Standalone Binary Tarball
echo "==> Packaging tar.gz release for macOS ${ARCH}..."
TAR_STAGE="$(mktemp -d -t dag-tar-XXXXXX)"
mkdir -p "${TAR_STAGE}/dag-${VERSION}"
cp "${STAGE_DIR}/dag" "${TAR_STAGE}/dag-${VERSION}/"
cp LICENSE "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true
cp README.md "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true
cp docs/dag.md "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true
cp docs/dag_replay.md "${TAR_STAGE}/dag-${VERSION}/" 2>/dev/null || true
cp man/dag.1 "${TAR_STAGE}/dag-${VERSION}/"                    # the manual page (generated from docs/dag.md: make man)

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
cp docs/dag_replay.md "${DMG_STAGE}/" 2>/dev/null || true
cp man/dag.1 "${DMG_STAGE}/"

cat << 'EOF' > "${DMG_STAGE}/INSTALL.txt"
DAG (DNS Anomaly Generator) - Installation Guide

To install the `dag` command into your system:
  1. Open Terminal
  2. Copy the binary to /usr/local/bin:
     sudo cp /Volumes/DAG/bin/dag /usr/local/bin/
  3. Ensure it is executable:
     sudo chmod +x /usr/local/bin/dag
  4. The manual page (man dag):
     sudo mkdir -p /usr/local/share/man/man1
     sudo cp /Volumes/DAG/dag.1 /usr/local/share/man/man1/

To verify:
  dag www.google.com A @8.8.8.8
EOF

hdiutil create -volname "DAG" -srcfolder "${DMG_STAGE}" -ov -format UDZO "${OUT_DIR}/dag-${VERSION}-macos-${ARCH}.dmg"

# Cleanup
rm -rf "${STAGE_DIR}" "${DMG_STAGE}"

echo "==> macOS packages generated in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"/dag*
